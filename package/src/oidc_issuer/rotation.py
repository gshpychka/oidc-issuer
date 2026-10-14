"""Key rotation: generates, publishes, activates, retires and deletes the
issuer's keys, and writes the JWKS relying parties verify tokens with.

A key goes through:
- pending: published, not signing yet, until relying parties' cached key sets
  include it (jwksCacheSeconds), or at once when no key can sign;
- active: the one key that signs, for rotationIntervalSeconds, or until it
  stops working (its sealed auth value no longer opens after a PCR 7 change,
  or the TPM2 was cleared), or until a replacement is requested;
- retired: still published while tokens it signed are valid, then deleted.

Every run checks each key against this TPM2: only keys it holds, with the
attributes that keep them inside it, are published.
"""

import enum
import fcntl
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from . import keys
from .config import Config
from .keys import Key
from .log import log
from .tpm import (
    ALGORITHM,
    AUTH_BYTES,
    RESIDENT_ATTRIBUTES,
    PublicKey,
    Tpm,
    TpmError,
    public_key_of,
    verify,
)

PROBE = b"oidc-issuer probe"
# leeway for relying parties whose clocks run behind this machine's
CLOCK_SKEW_SECONDS = 60


class Health(enum.Enum):
    # this TPM2 holds it, and it signs
    SIGNS = enum.auto()
    # this TPM2 holds it, and it does not sign: retired, or its auth value no
    # longer unseals
    RESIDENT = enum.auto()
    # not a key this TPM2 holds with the resident attributes and recorded public half
    FOREIGN = enum.auto()


def unseal(config: Config, sealed: Path, plaintext: Path) -> bool:
    result = subprocess.run(
        [
            config["systemdCreds"],
            "decrypt",
            f"--name={config['keyFiles']['auth']}",
            sealed,
            plaintext,
        ],
        check=False,
    )
    return result.returncode == 0


def check(config: Config, tpm: Tpm, primary: Path, key: Key, workdir: Path) -> Health:
    names = config["keyFiles"]
    scratch = workdir / key.kid
    scratch.mkdir()
    context = scratch / "key.ctx"
    try:
        tpm.load(
            primary,
            key.directory / names["public"],
            key.directory / names["private"],
            context,
        )
        attributes, public = tpm.read_public(context, scratch / "key.pem")
    except TpmError:
        return Health.FOREIGN
    if not attributes >= RESIDENT_ATTRIBUTES or public_key_of(public) != key.public:
        return Health.FOREIGN
    # a retired key only needs to stay publishable
    if key.retired is not None:
        return Health.RESIDENT
    auth = scratch / "auth"
    if not unseal(config, key.directory / names["auth"], auth):
        return Health.RESIDENT
    try:
        signature = tpm.sign(context, auth, PROBE, scratch)
    except TpmError:
        return Health.RESIDENT
    return Health.SIGNS if verify(key.public, PROBE, signature) else Health.RESIDENT


def generate(config: Config, tpm: Tpm, primary: Path, workdir: Path, now: int) -> Key:
    """Has the TPM2 generate a new key, checked to sign, and stores it pending."""
    names = config["keyFiles"]
    scratch = workdir / "new"
    scratch.mkdir()
    auth = scratch / "auth"
    auth.write_text(f"hex:{secrets.token_hex(AUTH_BYTES)}")
    tpm.create(primary, auth, scratch / names["public"], scratch / names["private"])
    context = scratch / "key.ctx"
    tpm.load(primary, scratch / names["public"], scratch / names["private"], context)
    _, public_key = tpm.read_public(context, scratch / "key.pem")
    public = public_key_of(public_key)
    if not verify(public, PROBE, tpm.sign(context, auth, PROBE, scratch)):
        raise TpmError("the new key's probe signature does not verify")

    directory = Path(config["stateDirectory"]) / public["kid"]
    directory.mkdir(mode=0o700)
    for name in (names["public"], names["private"]):
        shutil.copyfile(scratch / name, directory / name)
    # host+tpm2 needs both this machine's TPM2 and the root-only host key in
    # /var/lib/systemd to unseal. PCR 7 holds the Secure Boot state, so the
    # TPM2 refuses to unseal under any other boot chain: another OS on the
    # same disk, or anything else an enrolled CA lets boot. A Secure Boot key
    # or dbx update changes PCR 7 too, and the next check replaces the key.
    # The embedded name must match the unit's LoadCredentialEncrypted=.
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
        raise TpmError("systemd-creds could not seal the auth value")
    key = Key(
        directory=directory, public=public, created=now, activated=None, retired=None
    )
    key.save(config)
    return key


def publish(config: Config, published: list[PublicKey]) -> None:
    jwks = Path(config["jwksFile"])
    staged = jwks.with_name(f"{jwks.name}.new")
    document = {
        "keys": [
            {**key, "kty": "EC", "crv": "P-256", "alg": ALGORITHM, "use": "sig"}
            for key in published
        ]
    }
    staged.write_text(json.dumps(document))
    staged.chmod(0o644)
    os.replace(staged, jwks)


def rotate(config: Config) -> int:
    tpm = Tpm(Path(config["tpm2Tools"]), config["tcti"])
    state = Path(config["stateDirectory"])
    replace_request = state / config["replaceRequest"]
    now = int(time.time())
    # one run at a time; plaintext auth values stay in the runtime directory, a tmpfs
    with (
        (state / ".lock").open("w") as lock,
        tempfile.TemporaryDirectory(dir=os.environ["RUNTIME_DIRECTORY"]) as scratch,
    ):
        fcntl.flock(lock, fcntl.LOCK_EX)
        workdir = Path(scratch)
        try:
            primary = tpm.primary(workdir)
        except TpmError as error:
            log(f"rotation skipped: {error}; is there a usable TPM2?")
            return 1

        stored = keys.load(config)
        health = {key.kid: check(config, tpm, primary, key, workdir) for key in stored}
        for key in stored:
            if key.retired is None and health[key.kid] is not Health.SIGNS:
                log(
                    f"retired {key.kid}: {health[key.kid].name.lower()}, it cannot sign"
                )
                key.retired = now
                key.save(config)

        active = next((key for key in stored if key.active), None)
        pending = next((key for key in stored if key.pending), None)
        due = (
            active is None
            or replace_request.exists()
            or now - active.activated >= config["rotationIntervalSeconds"]
        )
        if pending is None and due:
            try:
                pending = generate(config, tpm, primary, workdir, now)
            except TpmError as error:
                log(f"could not generate a key: {error}")
                return 1
            stored.append(pending)
            health[pending.kid] = Health.SIGNS
            log(f"generated {pending.kid}")
        # a pending key is the requested replacement
        replace_request.unlink(missing_ok=True)

        # A key signs once cached key sets include it. With no key that can
        # sign, waiting gains nothing.
        if pending is not None and (
            active is None or now - pending.created >= config["jwksCacheSeconds"]
        ):
            if active is not None:
                active.retired = now
                active.save(config)
            pending.activated = now
            pending.save(config)
            active = pending
            log(f"activated {active.kid}")
        keys.link_active(config, active)

        expiry = config["tokenLifetimeSeconds"] + CLOCK_SKEW_SECONDS
        for key in stored:
            if key.retired is not None and now - key.retired >= expiry:
                shutil.rmtree(key.directory)
                log(f"deleted {key.kid}")
        publish(
            config,
            [
                key.public
                for key in stored
                if key.directory.exists() and health[key.kid] is not Health.FOREIGN
            ],
        )
    return 0
