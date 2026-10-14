"""Signs one token for the caller of an accepted connection.

systemd starts `serve` per connection (Accept=yes) with the accepted socket as
stdin, and the active key's files as credentials. The caller is identified by
the UID the kernel recorded when it connected (SO_PEERCRED). Nothing is read
from the connection, so there is no request to parse or forge. A declared
client gets one JSON line back: {"token": ..., "expires_at": ...}; anyone else
gets {"error": ...}.
"""

import json
import os
import pwd
import socket
import struct
import sys
import tempfile
import time
import uuid
from pathlib import Path

from .config import Config
from .log import log
from .tpm import ALGORITHM, PublicKey, Tpm, TpmError, b64url, jws_signature, verify

# struct ucred: pid, uid, gid
UCRED = struct.Struct("3i")


class IssuerError(Exception):
    pass


def encode_token(config: Config, claims: dict[str, str | int]) -> str:
    """A compact JWS (RFC 7515) of the claims, signed by the active key."""
    # systemd copied the active key's files into this per-service, in-memory
    # directory, the auth value decrypted
    credentials = Path(os.environ["CREDENTIALS_DIRECTORY"])
    names = config["keyFiles"]
    metadata = json.loads((credentials / names["metadata"]).read_text())
    public: PublicKey = {"kid": metadata["kid"], "x": metadata["x"], "y": metadata["y"]}

    header = {"alg": ALGORITHM, "kid": public["kid"], "typ": "JWT"}
    signing_input = ".".join(
        b64url(json.dumps(part, separators=(",", ":")).encode())
        for part in (header, claims)
    ).encode()
    tpm = Tpm(Path(config["tpm2Tools"]), config["tcti"])
    try:
        with tempfile.TemporaryDirectory() as scratch:
            workdir = Path(scratch)
            context = workdir / "key.ctx"
            tpm.load(
                tpm.primary(workdir),
                credentials / names["public"],
                credentials / names["private"],
                context,
            )
            der = tpm.sign(context, credentials / names["auth"], signing_input, workdir)
    except TpmError as error:
        raise IssuerError(str(error)) from error
    # A token relying parties can't verify is useless, and a mix-up here would
    # otherwise only show as a rejection by AWS.
    if not verify(public, signing_input, der):
        raise IssuerError(
            f"the TPM2 key does not match the public half of {public['kid']}"
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
        log(f"refused {caller}: not in services.oidc-issuer.simple.clients")
        reply(conn, {"error": f"{user or f'uid {uid}'} is not an OIDC issuer client"})
        return 0

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
        token = encode_token(config, claims)
    except IssuerError as error:
        log(f"refused {caller}: {error}")
        reply(conn, {"error": str(error)})
        return 1
    reply(conn, {"token": token, "expires_at": claims["exp"]})
    log(f"issued {claims['jti']} sub={claims['sub']} exp={claims['exp']} to {caller}")
    return 0
