#!/usr/bin/env python3
"""
fetch_asn.py — sapics/ip-location-db에서 최신 ASN↔IPv4 매핑 데이터 다운로드

사용법:
    python3 scripts/fetch_asn.py              # 다운로드 후 저장
    python3 scripts/fetch_asn.py --check      # 업데이트 필요 여부만 확인
"""

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT    = Path(__file__).parent.parent
OUT_CSV = ROOT / "data" / "asn-ipv4.csv"
META    = ROOT / "data" / "asn-meta.json"

ASN_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/asn/asn-ipv4.csv"


def md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_meta() -> dict:
    if META.exists():
        with open(META) as f:
            return json.load(f)
    return {}


def save_meta(rows: int, checksum: str) -> None:
    meta = {
        "source":    ASN_URL,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "rows":      rows,
        "md5":       checksum,
    }
    with open(META, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"📋 Metadata saved → {META}")


def fetch(check_only: bool = False) -> None:
    print(f"🌐 Fetching {ASN_URL} ...")
    req = urllib.request.Request(
        ASN_URL,
        headers={"User-Agent": "anonymous-vps-intel/1.0"}
    )

    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()

    rows = data.count(b"\n")
    new_md5 = hashlib.md5(data).hexdigest()
    size_mb = len(data) / 1_048_576

    print(f"   Size : {size_mb:.1f} MB  |  Rows: {rows:,}  |  MD5: {new_md5[:12]}…")

    meta = load_meta()
    if meta.get("md5") == new_md5:
        print("✅ Already up-to-date, no changes.")
        return

    if check_only:
        print("⚠️  Update available. Run without --check to apply.")
        return

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_CSV, "wb") as f:
        f.write(data)

    save_meta(rows, new_md5)
    prev = meta.get("updated_at", "never")
    print(f"✅ Saved → {OUT_CSV}  (previous: {prev})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch latest ASN IPv4 data from sapics/ip-location-db")
    parser.add_argument("--check", action="store_true", help="업데이트 필요 여부만 확인 (저장 안 함)")
    args = parser.parse_args()
    fetch(check_only=args.check)


if __name__ == "__main__":
    main()
