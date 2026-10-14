"""The issuer's signing keys on disk: a directory per key in the state
directory, named by its kid, with the TPM2's wrapped key, its sealed auth
value, and its metadata (public half and lifecycle times)."""

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .tpm import PublicKey


@dataclass
class Key:
    directory: Path
    public: PublicKey
    # when it was generated, and published
    created: int
    # when it started signing; None while it waits to be cached by relying parties
    activated: int | None
    # when it stopped signing; it stays published while its tokens are valid
    retired: int | None

    @property
    def kid(self) -> str:
        return self.public["kid"]

    @property
    def pending(self) -> bool:
        return self.activated is None and self.retired is None

    @property
    def active(self) -> bool:
        return self.activated is not None and self.retired is None

    def save(self, config: Config) -> None:
        metadata = self.directory / config["keyFiles"]["metadata"]
        staged = metadata.with_suffix(".new")
        staged.write_text(
            json.dumps(
                {
                    **self.public,
                    "created": self.created,
                    "activated": self.activated,
                    "retired": self.retired,
                }
            )
        )
        os.replace(staged, metadata)


def load(config: Config) -> list[Key]:
    """Every key directory with metadata, oldest first."""
    keys = []
    for directory in Path(config["stateDirectory"]).iterdir():
        metadata = directory / config["keyFiles"]["metadata"]
        if directory.is_symlink() or not metadata.is_file():
            continue
        fields = json.loads(metadata.read_text())
        keys.append(
            Key(
                directory=directory,
                public={"kid": fields["kid"], "x": fields["x"], "y": fields["y"]},
                created=fields["created"],
                activated=fields["activated"],
                retired=fields["retired"],
            )
        )
    return sorted(keys, key=lambda key: key.created)


def link_active(config: Config, key: Key | None) -> None:
    """Points the active link at key's directory, or removes it."""
    link = Path(config["stateDirectory"]) / config["activeLink"]
    if key is None:
        link.unlink(missing_ok=True)
        return
    staged = link.with_name(f"{link.name}.new")
    staged.unlink(missing_ok=True)
    staged.symlink_to(key.directory.name)
    os.replace(staged, link)
