#!/usr/bin/env python3
"""
pipeline.py — Anonymous VPS Intelligence detection-first pipeline.

실행 순서:
    1. fetch_asn.py               — ASN DB 다운로드
    2. validate_data.py           — JSON-compatible YAML 검증
    3. generate_legacy_bridge.py  — legacy provider CSV 재생성
    4. generate_provider_ranges.py — provider inventory CIDR 생성
    5. generate_incident_iocs.py  — incident IOC CSV 생성
    6. generate_high_risk_cidrs.py — high-risk CIDR CSV 생성
    7. generate_queries.py        — Logpresso 쿼리 생성
    8. generate_sigma.py          — Sigma 룰 생성
"""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT    = Path(__file__).parent.parent
SCRIPTS = Path(__file__).parent


def run(script: str, extra_args: list[str] = []) -> bool:
    cmd = [sys.executable, str(SCRIPTS / script)] + extra_args
    print(f"\n{'─'*60}", flush=True)
    print(f"▶  {' '.join(cmd)}", flush=True)
    print(f"{'─'*60}", flush=True)
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

    shared_extra: list[str] = []
    query_extra: list[str] = []
    if args.dry_run:
        shared_extra.append("--dry-run")
        query_extra.append("--dry-run")
    if args.vendor:
        query_extra += ["--vendor", args.vendor]

    print("🚀 Anonymous VPS Intelligence Pipeline", flush=True)
    print(f"   skip-fetch : {args.skip_fetch}", flush=True)
    print(f"   vendor     : {args.vendor or '(all)'}", flush=True)
    print(f"   dry-run    : {args.dry_run}", flush=True)

    steps: list[tuple[str, list[str]]] = []

    # Step 1: fetch ASN
    if not args.skip_fetch:
        steps.append(("fetch_asn.py", []))
    else:
        print("\n⏭  Skipping ASN fetch (--skip-fetch)", flush=True)

    steps.extend(
        [
            ("validate_data.py", []),
            ("generate_legacy_bridge.py", shared_extra),
            ("generate_provider_ranges.py", shared_extra),
            ("generate_incident_iocs.py", []),
            ("generate_high_risk_cidrs.py", []),
            ("generate_queries.py", query_extra),
            ("generate_sigma.py", query_extra),
        ]
    )

    for script, script_args in steps:
        ok = run(script, script_args)
        if not ok:
            print(f"\n❌ Failed at {script}. Pipeline stopped.", flush=True)
            sys.exit(1)

    print(f"\n{'='*60}", flush=True)
    print("✅ Pipeline complete.", flush=True)

    # 요약 출력
    ranges_file = ROOT / "generated" / "detection" / "provider-ranges.csv"
    incident_file = ROOT / "generated" / "detection" / "incident-iocs.csv"
    high_risk_file = ROOT / "generated" / "detection" / "high-risk-cidrs.csv"
    queries_dir = ROOT / "queries" / "logpresso"
    if ranges_file.exists():
        lines = ranges_file.read_text().count("\n")
        print(f"   Provider ranges : {lines - 1} rows  ({ranges_file})", flush=True)
    if incident_file.exists():
        lines = incident_file.read_text().count("\n")
        print(f"   Incident IOCs   : {lines - 1} rows  ({incident_file})", flush=True)
    if high_risk_file.exists():
        lines = high_risk_file.read_text().count("\n")
        print(f"   High-risk CIDRs : {lines - 1} rows  ({high_risk_file})", flush=True)
    if queries_dir.exists():
        qfiles = list(queries_dir.glob("*.logpresso"))
        print(f"   Queries    : {len(qfiles)} files ({queries_dir})", flush=True)
    sigma_dir = ROOT / "queries" / "sigma"
    if sigma_dir.exists():
        sfiles = list(sigma_dir.glob("*.yml"))
        print(f"   Sigma rules: {len(sfiles)} files ({sigma_dir})", flush=True)
    print(f"{'='*60}", flush=True)


if __name__ == "__main__":
    main()
