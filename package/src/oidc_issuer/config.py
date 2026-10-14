"""The issuer's settings: the JSON file every command takes."""

import json
from pathlib import Path
from typing import TypedDict


class KeyFiles(TypedDict):
    """A key's files in <stateDirectory>/<kid>/. Each is also the name of the
    credential systemd hands the file over as."""

    public: str  # TPM2B_PUBLIC
    private: str  # TPM2B_PRIVATE, wrapped by this TPM2's storage key
    auth: str  # the key's auth value, sealed with systemd-creds
    metadata: str  # the public half and lifecycle times, JSON


class Config(TypedDict):
    # the issuer's name, also the prefix of every subject
    name: str
    issuer: str
    audience: str
    clients: list[str]
    tokenLifetimeSeconds: int
    rotationIntervalSeconds: int
    jwksCacheSeconds: int
    stateDirectory: str
    # symlink in stateDirectory to the active key's directory
    activeLink: str
    # file in stateDirectory whose presence asks for the active key's replacement
    replaceRequest: str
    jwksFile: str
    keyFiles: KeyFiles
    systemdCreds: str
    tpm2Tools: str
    tcti: str


def load(path: Path) -> Config:
    return json.loads(path.read_text())
