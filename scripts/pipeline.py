#!/usr/bin/env python3
"""
pipeline.py — Anonymous VPS Intelligence 파이프라인 통합 진입점

실행 순서:
    1. fetch_asn.py      — sapics에서 최신 ASN DB 다운로드
    2. generate_ranges.py — ASN 조인 → IP 대역 CSV 생성
    3. generate_queries.py — IP 대역 → Logpresso 쿼리 생성

사용법:
    python3 scripts/pipeline.py                        # 전체 실행
    python3 scripts/pipeline.py --skip-fetch           # ASN 다운로드 생략
    python3 scripts/pipeline.py --vendor BitLaunch     # 특정 공급자만
    python3 scripts/pipeline.py --dry-run              # 변경 없이 미리보기
"""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT    = Path(__file__).parent.parent
SCRIPTS = Path(__file__).parent


def run(script: str, extra_args: list[str] = []) -> bool:
    cmd = [sys.executable, str(SCRIPTS / script)] + extra_args
    print(f"\n{'─'*60}")
    print(f"▶  {' '.join(cmd)}")
    print(f"{'─'*60}")
    result = subprocess.run(cmd, cwd=ROOT)
    return result.returncode == 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Anonymous VPS Intelligence pipeline")
    parser.add_argument("--skip-fetch", action="store_true",
                        help="ASN DB 다운로드 생략 (기존 파일 사용)")
    parser.add_argument("--vendor", metavar="NAME",
                        help="특정 공급자만 처리 (예: BitLaunch)")
    parser.add_argument("--dry-run", action="store_true",
                        help="파일 저장 없이 미리보기")
    args = parser.parse_args()

    extra = []
    if args.vendor:
        extra += ["--vendor", args.vendor]
    if args.dry_run:
        extra += ["--dry-run"]

    print("🚀 Anonymous VPS Intelligence Pipeline")
    print(f"   skip-fetch : {args.skip_fetch}")
    print(f"   vendor     : {args.vendor or '(all)'}")
    print(f"   dry-run    : {args.dry_run}")

    steps = []

    # Step 1: fetch ASN
    if not args.skip_fetch:
        steps.append(("fetch_asn.py", []))
    else:
        print("\n⏭  Skipping ASN fetch (--skip-fetch)")

    # Step 2: generate ranges
    steps.append(("generate_ranges.py", extra))

    # Step 3: generate queries
    steps.append(("generate_queries.py", extra))

    # Step 4: generate sigma rules
    steps.append(("generate_sigma.py", extra))

    for script, script_args in steps:
        ok = run(script, script_args)
        if not ok:
            print(f"\n❌ Failed at {script}. Pipeline stopped.")
            sys.exit(1)

    print(f"\n{'='*60}")
    print("✅ Pipeline complete.")

    # 요약 출력
    ranges_file = ROOT / "data" / "ip-ranges" / "known-providers.csv"
    queries_dir = ROOT / "queries" / "logpresso"
    if ranges_file.exists():
        lines = ranges_file.read_text().count("\n")
        print(f"   IP ranges  : {lines - 1} rows  ({ranges_file})")
    if queries_dir.exists():
        qfiles = list(queries_dir.glob("*.logpresso"))
        print(f"   Queries    : {len(qfiles)} files ({queries_dir})")
    sigma_dir = ROOT / "queries" / "sigma"
    if sigma_dir.exists():
        sfiles = list(sigma_dir.glob("*.yml"))
        print(f"   Sigma rules: {len(sfiles)} files ({sigma_dir})")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
