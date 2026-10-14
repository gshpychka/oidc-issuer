"""oidc-issuer: sign short-lived OIDC tokens for local Unix users with keys
inside this machine's TPM2, and rotate those keys."""

import argparse
import sys
from pathlib import Path

from . import config, rotation, signer


def main() -> int:
    parser = argparse.ArgumentParser(prog="oidc-issuer", description=__doc__)
    parser.add_argument(
        "command",
        choices=["serve", "rotate"],
        help="serve: sign a token for an accepted connection; rotate: one rotation step",
    )
    parser.add_argument("config", type=Path, help="JSON config written by Nix")
    args = parser.parse_args()
    settings = config.load(args.config)
    if args.command == "serve":
        return signer.serve(settings)
    return rotation.rotate(settings)


if __name__ == "__main__":
    sys.exit(main())
