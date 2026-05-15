"""`python -m ironcontext <subcommand> …` — forwards to the Rust binary so the
Python wrapper exposes the same CLI surface as the native binary."""

from __future__ import annotations

import os
import sys

from . import find_binary, BinaryNotFound


def main() -> int:
    try:
        binary = find_binary()
    except BinaryNotFound as e:
        print(f"ironcontext: {e}", file=sys.stderr)
        return 127
    os.execvp(str(binary), [str(binary), *sys.argv[1:]])
    return 0  # unreachable


if __name__ == "__main__":
    sys.exit(main())
