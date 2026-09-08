from __future__ import annotations

import argparse
from pathlib import Path

from .secure_compile import verify_security_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Chromaplex Secure Compile Gate output")
    parser.add_argument("binary", type=Path, help="compiled binary/bundle")
    parser.add_argument("--manifest", type=Path, help="security manifest; defaults to <binary>.security.json")
    args = parser.parse_args(argv)
    manifest = args.manifest or args.binary.with_name(args.binary.name + ".security.json")
    ok, problems = verify_security_manifest(args.binary, manifest)
    if ok:
        print(f"PASS: {args.binary} matches {manifest}")
        return 0
    print("FAIL: Secure build verification failed")
    for problem in problems:
        print(f"- {problem}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
