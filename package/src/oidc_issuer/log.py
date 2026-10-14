import sys


def log(message: str) -> None:
    """To stderr, which systemd sends to the journal."""
    print(message, file=sys.stderr, flush=True)
