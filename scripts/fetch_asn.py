#!/usr/bin/env python3
"""
fetch_asn.py — sapics/ip-location-db에서 최신 IPv4 데이터 다운로드

두 개의 GeoLite2 기반 파일을 받는다:
  - ASN↔IPv4 (start,end,asn,"org명")  → data/asn-ipv4.csv
  - 국가↔IPv4 (start,end,country_code) → data/country-ipv4.csv

사용법:
    python3 scripts/fetch_asn.py              # 다운로드 후 저장
    python3 scripts/fetch_asn.py --check      # 업데이트 필요 여부만 확인
"""

import argparse
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
DATA = ROOT / "data"

# sapics가 2026-06 저장소를 소스별 디렉토리로 재편하면서 기존 `asn/asn-ipv4.csv` 경로가
# 제거됨(404). GeoLite2 기반 파일이 기존 데이터와 동일 포맷(start,end,asn,"org명")이며
# org명이 채워져 있어 validate_data.py의 ASN 소유권 검증을 그대로 유지한다.
# (dbip-asn-ipv4.csv 는 org명 컬럼이 비어 있어 사용 불가)
ASN_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-asn/geolite2-asn-ipv4.csv"
# 같은 저장소의 국가↔IPv4 매핑(start,end,country_code). generate_location_context.py가
# 추적 ASN 대역을 실제 지오로케이션 국가와 교차하여 KR-localized 대역을 자동 추출할 때 사용한다.
COUNTRY_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv4.csv"

SOURCES = [
    (ASN_URL, DATA / "asn-ipv4.csv", DATA / "asn-meta.json"),
    (COUNTRY_URL, DATA / "country-ipv4.csv", DATA / "country-meta.json"),
]


def load_meta(meta_path: Path) -> dict:
    if meta_path.exists():
        with open(meta_path) as f:
            return json.load(f)
    return {}


def save_meta(meta_path: Path, url: str, rows: int, checksum: str) -> None:
    meta = {
        "source": url,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "rows": rows,
        "md5": checksum,
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"📋 Metadata saved → {meta_path}")


def fetch_one(url: str, out_csv: Path, meta_path: Path, check_only: bool) -> None:
    print(f"🌐 Fetching {url} ...")
    req = urllib.request.Request(url, headers={"User-Agent": "anonymous-vps-intel/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()

    rows = data.count(b"\n")
    new_md5 = hashlib.md5(data).hexdigest()
    size_mb = len(data) / 1_048_576
    print(f"   Size : {size_mb:.1f} MB  |  Rows: {rows:,}  |  MD5: {new_md5[:12]}…")

    meta = load_meta(meta_path)
    if meta.get("md5") == new_md5:
        print("✅ Already up-to-date, no changes.")
        return

    if check_only:
        print("⚠️  Update available. Run without --check to apply.")
        return

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "wb") as f:
        f.write(data)
    save_meta(meta_path, url, rows, new_md5)
    prev = meta.get("updated_at", "never")
    print(f"✅ Saved → {out_csv}  (previous: {prev})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch latest IPv4 data from sapics/ip-location-db")
    parser.add_argument("--check", action="store_true", help="업데이트 필요 여부만 확인 (저장 안 함)")
    args = parser.parse_args()
    for url, out_csv, meta_path in SOURCES:
        fetch_one(url, out_csv, meta_path, check_only=args.check)


if __name__ == "__main__":
    main()
