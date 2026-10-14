"""ECDSA P-256 signing keys inside this machine's TPM2, driven with tpm2-tools.

A key is generated inside the TPM2 and never leaves it. On disk is only the key
wrapped by the TPM2's own storage key, which only this TPM2 can load, and
every use of the key needs its auth value.
"""

import base64
import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# ES256 is ECDSA over P-256 with SHA-256, matching the TPM2 key below.
ALGORITHM = "ES256"
CURVE = ec.SECP256R1
SIGNATURE_HASH = hashes.SHA256
COORDINATE_BYTES = 32

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
# The attributes that keep a key inside the TPM2 that generated it.
RESIDENT_ATTRIBUTES = frozenset({"fixedtpm", "fixedparent", "sensitivedataorigin"})
# Bytes in an auth value. A TPM2 caps it at the key's name hash size (SHA-256).
AUTH_BYTES = 32


class PublicKey(TypedDict):
    kid: str
    x: str
    y: str


class TpmError(Exception):
    pass


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


def verify(public: PublicKey, message: bytes, der: bytes) -> bool:
    """Whether der is public's signature of message, as a relying party checks it."""
    numbers = ec.EllipticCurvePublicNumbers(
        b64url_int(public["x"]), b64url_int(public["y"]), CURVE()
    )
    try:
        numbers.public_key().verify(der, message, ec.ECDSA(SIGNATURE_HASH()))
    except InvalidSignature:
        return False
    return True


def jws_signature(der: bytes) -> bytes:
    """JWS has ECDSA signatures as fixed-size r||s, not DER (RFC 7518 3.4)."""
    r, s = decode_dss_signature(der)
    return r.to_bytes(COORDINATE_BYTES, "big") + s.to_bytes(COORDINATE_BYTES, "big")


@dataclass(frozen=True)
class Tpm:
    """This machine's TPM2. Each command is a separate tpm2-tools process,
    passing the TPM2's objects on in context files. Through the kernel's
    resource manager (tcti device:/dev/tpmrm0), every object a process loaded
    is flushed when it exits, so a killed command leaves nothing behind in the
    TPM2."""

    tools: Path
    tcti: str

    def run(self, tool: str, *args: str | Path, input: bytes | None = None) -> str:
        """Runs a tpm2-tools command; its errors go to our stderr (the journal)."""
        try:
            result = subprocess.run(
                [self.tools / f"tpm2_{tool}", *args],
                input=input,
                env={"TPM2TOOLS_TCTI": self.tcti},
                stdout=subprocess.PIPE,
                check=True,
            )
        except subprocess.CalledProcessError as error:
            message = f"tpm2_{tool} failed (exit status {error.returncode})"
            raise TpmError(message) from error
        return result.stdout.decode()

    def primary(self, workdir: Path) -> Path:
        """The parent of every signing key, loaded; returns its context file."""
        context = workdir / "primary.ctx"
        self.run("createprimary", *PRIMARY_KEY, "-c", context)
        return context

    def create(self, primary: Path, auth: Path, public: Path, private: Path) -> None:
        """Has the TPM2 generate a signing key with this auth value, and writes
        its wrapped halves."""
        self.run(
            "create",
            "-C",
            primary,
            *SIGNING_KEY,
            # tpm2-tools reads the auth value from the file as a password
            # string: cut at the first NUL, trailing newlines dropped. So it is
            # stored hex-encoded, with the "hex:" prefix that tells tpm2-tools
            # to decode it.
            "-p",
            f"file:{auth}",
            "-u",
            public,
            "-r",
            private,
        )

    def load(self, primary: Path, public: Path, private: Path, context: Path) -> None:
        """Loads a key this TPM2 wrapped; fails for any other TPM2's key."""
        self.run("load", "-C", primary, "-u", public, "-r", private, "-c", context)

    def read_public(
        self, context: Path, pem: Path
    ) -> tuple[frozenset[str], ec.EllipticCurvePublicKey]:
        """A loaded key's attributes and public key."""
        report = self.run(
            "readpublic", "-c", context, "-f", "pem", "-o", pem
        ).splitlines()
        # "attributes:", then "  value: fixedtpm|fixedparent|..."
        value = report[report.index("attributes:") + 1].strip().removeprefix("value:")
        key = serialization.load_pem_public_key(pem.read_bytes())
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
            key.curve, CURVE
        ):
            raise TpmError("the key is not a P-256 key")
        return frozenset(value.strip().split("|")), key

    def sign(self, key: Path, auth: Path, message: bytes, workdir: Path) -> bytes:
        """Signs SHA-256(message) with a loaded key. Returns a DER signature."""
        signature = workdir / "signature"
        self.run(
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
