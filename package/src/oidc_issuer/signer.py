"""oidc-issuer: sign short-lived OIDC tokens for local Unix users.

`serve` handles one connection. systemd starts it per connection
(oidc-issuer.socket, Accept=yes) with the accepted socket as stdin. The caller
is identified by the UID the kernel recorded when it connected (SO_PEERCRED).
Nothing is read from the connection, so there is no request to parse or forge.
A declared client gets one JSON line back: {"token": ..., "expires_at": ...};
anyone else gets {"error": ...}.

`keygen` has the TPM2 generate a signing key that never leaves it, seals the
key's auth value with systemd-creds, and prints the public half for the Nix
config.

The signing key lives in the TPM2. What is on disk is the key wrapped by the
TPM2's own storage key, which only this TPM2 can load, and is useless without
the auth value. The TPM2 refuses to export it, so whoever can use the key
(root on this machine) can sign with it while they can reach this TPM2, but
can't take it elsewhere. The TPM2 is driven with tpm2-tools.
"""

import argparse
import base64
import hashlib
import json
import os
import pwd
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# ES256 is ECDSA over P-256 with SHA-256, matching the published JWKS and the
# TPM2 key below.
ALGORITHM = "ES256"
CURVE = ec.SECP256R1
SIGNATURE_HASH = hashes.SHA256
COORDINATE_BYTES = 32
# struct ucred: pid, uid, gid
UCRED = struct.Struct("3i")

# The parent of every signing key: a primary key in the owner (storage)
# hierarchy. The TPM2 derives it from the hierarchy's secret seed and this
# template, so creating it again yields the same key and it is never stored.
# Assumes the owner hierarchy has no auth value, the Linux default and what
# systemd-creds' own TPM2 sealing needs too. Clearing the TPM2 (from the
# firmware setup or Windows) replaces the seed, and with it every key.
PRIMARY_KEY = ["-C", "o", "-g", "sha256", "-G", "ecc256:aes128cfb"]
SIGNING_KEY = [
    "-G",
    "ecc256:ecdsa-sha256",
    # fixedtpm, fixedparent: the TPM2 refuses to export or duplicate the key.
    # sensitivedataorigin: the TPM2 generated it, so it never existed outside.
    # userwithauth: every use needs the auth value.
    # noda: wrong auth values don't count towards the TPM2's dictionary-attack
    # lockout, which would lock this key along with every other one. The auth
    # value is 256 random bits, so guessing it is no concern.
    "-a",
    "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda",
]
# Bytes in an auth value. A TPM2 caps it at the key's name hash size (SHA-256).
AUTH_BYTES = 32


class PublicKey(TypedDict):
    kid: str
    x: str
    y: str


class KeyFiles(TypedDict):
    """A key's files in <stateDirectory>/<kid>/. Each is also the name of the
    credential systemd hands the file over as."""

    public: str  # TPM2B_PUBLIC
    private: str  # TPM2B_PRIVATE, wrapped by this TPM2's storage key
    auth: str  # the key's auth value, sealed with systemd-creds


class Config(TypedDict):
    """The issuer's settings: the JSON file both commands take."""

    name: str
    issuer: str
    audience: str
    tokenLifetimeSeconds: int
    clients: list[str]
    activeKey: PublicKey | None
    stateDirectory: str
    keyFiles: KeyFiles
    systemdCreds: str
    tpm2Tools: str
    tcti: str
    jwksCacheSeconds: int


class IssuerError(Exception):
    pass


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_int(value: str) -> int:
    padded = value + "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")


def public_key_of(key: ec.EllipticCurvePublicKey) -> PublicKey:
    numbers = key.public_numbers()
    x = b64url(numbers.x.to_bytes(COORDINATE_BYTES, "big"))
    y = b64url(numbers.y.to_bytes(COORDINATE_BYTES, "big"))
    # RFC 7638 thumbprint: the required members, sorted, without whitespace
    required = {"crv": "P-256", "kty": "EC", "x": x, "y": y}
    canonical = json.dumps(required, sort_keys=True, separators=(",", ":"))
    return {"kid": b64url(hashlib.sha256(canonical.encode()).digest()), "x": x, "y": y}


def verifier_of(public: PublicKey) -> ec.EllipticCurvePublicKey:
    """The published key, as AWS sees it."""
    numbers = ec.EllipticCurvePublicNumbers(
        b64url_int(public["x"]), b64url_int(public["y"]), CURVE()
    )
    return numbers.public_key()


def tpm2(
    config: Config, tool: str, *args: str | Path, input: bytes | None = None
) -> None:
    """Runs a tpm2-tools command; its errors go to our stderr (the journal)."""
    try:
        subprocess.run(
            [Path(config["tpm2Tools"]) / f"tpm2_{tool}", "-Q", *args],
            input=input,
            env={"TPM2TOOLS_TCTI": config["tcti"]},
            stdout=subprocess.DEVNULL,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        message = f"tpm2_{tool} failed (exit status {error.returncode})"
        raise IssuerError(message) from error


def tpm2_sign(
    config: Config, public: Path, private: Path, auth: Path, message: bytes
) -> bytes:
    """Signs SHA-256(message) with a key in this TPM2. Returns a DER signature.

    Each step is a separate tpm2-tools process, passing the TPM2's objects on
    in context files. Through the kernel's resource manager (tcti
    device:/dev/tpmrm0), every object a process loaded is flushed when it
    exits, so a killed instance leaves nothing behind in the TPM2.
    """
    with tempfile.TemporaryDirectory() as workdir:
        primary = Path(workdir) / "primary.ctx"
        key = Path(workdir) / "key.ctx"
        signature = Path(workdir) / "signature"
        tpm2(config, "createprimary", *PRIMARY_KEY, "-c", primary)
        tpm2(config, "load", "-C", primary, "-u", public, "-r", private, "-c", key)
        # tpm2-tools reads the auth value from the file as a password string:
        # cut at the first NUL, trailing newlines dropped. So it is stored
        # hex-encoded, with the "hex:" prefix that tells tpm2-tools to decode it.
        tpm2(
            config,
            "sign",
            "-c",
            key,
            "-p",
            f"file:{auth}",
            "-g",
            "sha256",
            "-s",
            "ecdsa",
            # "plain" for ECDSA is DER, as the cryptography library takes it
            "-f",
            "plain",
            "-o",
            signature,
            input=message,
        )
        return signature.read_bytes()


def verify(public: PublicKey, message: bytes, der: bytes) -> bool:
    try:
        verifier_of(public).verify(der, message, ec.ECDSA(SIGNATURE_HASH()))
    except InvalidSignature:
        return False
    return True


def jws_signature(der: bytes) -> bytes:
    """JWS has ECDSA signatures as fixed-size r||s, not DER (RFC 7518 3.4)."""
    r, s = decode_dss_signature(der)
    return r.to_bytes(COORDINATE_BYTES, "big") + s.to_bytes(COORDINATE_BYTES, "big")


def encode_token(
    config: Config, active: PublicKey, claims: dict[str, str | int]
) -> str:
    """A compact JWS (RFC 7515) of the claims, signed by the TPM2."""
    header = {"alg": ALGORITHM, "kid": active["kid"], "typ": "JWT"}
    signing_input = ".".join(
        b64url(json.dumps(part, separators=(",", ":")).encode())
        for part in (header, claims)
    ).encode()
    # systemd copied the key files into this per-service, in-memory directory,
    # the auth value decrypted
    credentials = Path(os.environ["CREDENTIALS_DIRECTORY"])
    names = config["keyFiles"]
    der = tpm2_sign(
        config,
        credentials / names["public"],
        credentials / names["private"],
        credentials / names["auth"],
        signing_input,
    )
    # A token AWS can't verify against the published JWKS is useless, and a
    # mix-up here would otherwise only show as a rejection by AWS.
    if not verify(active, signing_input, der):
        raise IssuerError(
            f"the TPM2 key does not match the published key {active['kid']}; "
            "check services.oidc-issuer.simple.signer.activeKid and services.oidc-issuer.simple.publicKeys"
        )
    return f"{signing_input.decode()}.{b64url(jws_signature(der))}"


def peer_credentials(conn: socket.socket) -> tuple[int, int]:
    """(pid, uid) of the connecting process, as the kernel recorded at connect()."""
    pid, uid, _gid = UCRED.unpack(
        conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, UCRED.size)
    )
    return pid, uid


def read_proc(pid: int, name: str) -> str:
    """A /proc file the caller controls, escaped like a bytes literal. A
    process can name itself (comm) or its cgroup anything: invalid UTF-8, or
    a newline that journald would turn into a forged log line of its own."""
    raw = Path(f"/proc/{pid}/{name}").read_bytes().removesuffix(b"\n")
    return repr(raw)[2:-1]


def describe_process(pid: int) -> str:
    """Best effort, for the audit log only: by now the PID may be another process."""
    try:
        command = read_proc(pid, "comm")
        cgroup = read_proc(pid, "cgroup")
    except OSError:
        return f"pid {pid}"
    # cgroup v2: a single "0::<path>" line
    return f"pid {pid} {command} in {cgroup.removeprefix('0::')}"


def reply(conn: socket.socket, message: dict[str, str | int]) -> None:
    conn.sendall(json.dumps(message).encode() + b"\n")


def serve(config: Config) -> int:
    conn = socket.socket(fileno=sys.stdin.fileno())
    pid, uid = peer_credentials(conn)
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        user = None
    caller = f"{user or f'uid {uid}'} ({describe_process(pid)})"

    if user is None or user not in config["clients"]:
        log(f"refused {caller}: not in services.oidc-issuer.simple.signer.clients")
        reply(conn, {"error": f"{user or f'uid {uid}'} is not an OIDC issuer client"})
        return 0

    active = config["activeKey"]
    now = int(time.time())
    claims = {
        "iss": config["issuer"],
        "sub": f"{config['name']}:{user}",
        "aud": config["audience"],
        "iat": now,
        "exp": now + config["tokenLifetimeSeconds"],
        "jti": str(uuid.uuid4()),
    }
    try:
        if active is None:
            raise IssuerError("no active signing key is configured")
        token = encode_token(config, active, claims)
    except IssuerError as error:
        log(f"refused {caller}: {error}")
        reply(conn, {"error": str(error)})
        return 1
    reply(conn, {"token": token, "expires_at": claims["exp"]})
    log(f"issued {claims['jti']} sub={claims['sub']} exp={claims['exp']} to {caller}")
    return 0


def create_key(config: Config, directory: Path, auth: Path) -> PublicKey:
    """Has the TPM2 generate a signing key with this auth value, and writes
    its wrapped files into directory."""
    names = config["keyFiles"]
    primary = directory / "primary.ctx"
    public_pem = directory / "public.pem"
    tpm2(config, "createprimary", *PRIMARY_KEY, "-c", primary)
    tpm2(
        config,
        "create",
        "-C",
        primary,
        *SIGNING_KEY,
        "-p",
        f"file:{auth}",
        "-u",
        directory / names["public"],
        "-r",
        directory / names["private"],
        "-f",
        "pem",
        "-o",
        public_pem,
    )
    key = serialization.load_pem_public_key(public_pem.read_bytes())
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, CURVE
    ):
        raise IssuerError("the TPM2 did not create a P-256 key")
    public = public_key_of(key)
    # the exact path serve takes, so a key that prints here signs there
    probe = b"oidc-issuer-keygen probe"
    der = tpm2_sign(
        config, directory / names["public"], directory / names["private"], auth, probe
    )
    if not verify(public, probe, der):
        raise IssuerError("the new key's probe signature does not verify")
    return public


def keygen(config: Config) -> int:
    if os.geteuid() != 0:
        log(
            "oidc-issuer-keygen: run as root; systemd-creds seals with the root-only host key"
        )
        return 1
    names = config["keyFiles"]
    # /run is a tmpfs, so the plaintext auth value never reaches a disk
    with tempfile.TemporaryDirectory(dir="/run") as workdir:
        new = Path(workdir)
        auth = new / "auth"
        auth.write_text(f"hex:{secrets.token_hex(AUTH_BYTES)}")
        try:
            public = create_key(config, new, auth)
        except IssuerError as error:
            log(f"oidc-issuer-keygen: {error}; is there a usable TPM2?")
            return 1

        directory = Path(config["stateDirectory"]) / public["kid"]
        directory.mkdir(mode=0o700)
        for name in (names["public"], names["private"]):
            shutil.copyfile(new / name, directory / name)
        # host+tpm2 needs both this machine's TPM2 and the root-only host key in
        # /var/lib/systemd to unseal. PCR 7 holds the Secure Boot state, so the
        # TPM2 refuses to unseal under any other boot chain: Windows on the
        # same disk, or anything else Microsoft's CA (enrolled for Windows)
        # lets boot. A Secure Boot key or dbx update changes PCR 7 too, and
        # then the key needs regenerating. The embedded name must match
        # LoadCredentialEncrypted=.
        sealed = subprocess.run(
            [
                config["systemdCreds"],
                "encrypt",
                "--with-key=host+tpm2",
                "--tpm2-pcrs=7",
                f"--name={names['auth']}",
                auth,
                directory / names["auth"],
            ],
            check=False,
        )
        if sealed.returncode != 0:
            shutil.rmtree(directory)
            log("oidc-issuer-keygen: systemd-creds could not seal the auth value")
            return 1
    print(f"""Created a new signing key in the TPM2; its files are in {directory}.

Publish it by adding this entry to services.oidc-issuer.simple.publicKeys and
deploying the publishing machine:

  {{
    kid = "{public["kid"]}";
    x = "{public["x"]}";
    y = "{public["y"]}";
  }}

Then wait {config["jwksCacheSeconds"]} seconds for cached key sets to pick it up, set
services.oidc-issuer.simple.signer.activeKid = "{public["kid"]}"; and deploy {config["name"]} to sign with it.""")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="oidc-issuer")
    parser.add_argument("command", choices=["serve", "keygen"])
    parser.add_argument("config", type=Path, help="JSON config written by Nix")
    args = parser.parse_args()
    config: Config = json.loads(args.config.read_text())
    if args.command == "serve":
        return serve(config)
    return keygen(config)


if __name__ == "__main__":
    sys.exit(main())
