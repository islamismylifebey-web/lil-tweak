"""Optional read-only R2 credential and bucket probe run inside the core."""

from __future__ import annotations

import os
import sys


def main(argv: list[str]) -> int:
    if argv == ["--check"]:
        print("R2 probe check: ok")
        return 0
    if argv:
        print("usage: verify_r2.py [--check]", file=sys.stderr)
        return 2
    try:
        import boto3

        client = boto3.client(
            "s3",
            endpoint_url=os.environ["LIL_TWEAK_EVIDENCE_ENDPOINT"],
            region_name="auto",
            aws_access_key_id=os.environ["LIL_TWEAK_R2_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["LIL_TWEAK_R2_SECRET_ACCESS_KEY"],
        )
        client.head_bucket(Bucket=os.environ["LIL_TWEAK_EVIDENCE_BUCKET"])
    except Exception:
        print("R2 read-only probe failed", file=sys.stderr)
        return 1
    print("R2 read-only probe: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
