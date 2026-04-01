# AGENT.md — Anonymous VPS Intelligence Project

## 프로젝트 목적

익명성 보장 및 가상화폐 결제가 가능한 VPS 서비스 목록을 **큐레이션**하고, 실제 APT/랜섬웨어 공격 사례와 연계하여 **Threat Intelligence 데이터**로 GitHub에 공개·공유하는 프로젝트입니다.

---

## 파일별 역할 (수동편집 vs 자동생성)

| 파일 | 성격 | 관리 방법 |
|------|------|-----------|
| `data/vps-providers.csv` | **소스 오브 트루스** | ✅ 직접 편집 |
| `data/asn-ipv4.csv` | ASN 참조 DB | 🔄 `fetch_asn.py` 자동 다운로드 |
| `data/ip-ranges/known-providers.csv` | IP 대역 목록 | ❌ 자동 생성 (직접 편집 금지) |
| `data/ip-ranges/notes.csv` | IP 대역 메모 | ✅ 직접 편집 (optional) |
| `queries/logpresso/*.logpresso` | 탐지 쿼리 | ❌ 자동 생성 (직접 편집 금지) |
| `reports/*.md` | 사례 분석 리포트 | ✅ 직접 편집 |

---

## 데이터 흐름

```
[직접 편집]
vps-providers.csv (vendor + ASN)
        +
asn-ipv4.csv  ←  fetch_asn.py (sapics GitHub에서 다운로드)
        ↓  generate_ranges.py
data/ip-ranges/known-providers.csv  (자동 생성)
        ↓  generate_queries.py
queries/logpresso/<vendor>.logpresso  (자동 생성)
queries/logpresso/all-vendors.logpresso
```

---

## 핵심 데이터 스키마: `data/vps-providers.csv`

| 컬럼 | 설명 |
|------|------|
| `vendor` | VPS 공급자 이름 |
| `domain` | 공식 도메인 |
| `asn` | AS 번호 (예: AS399629) — 없으면 파이프라인에서 건너뜀 |
| `asn_link` | bgp.tools 링크 |
| `shodan_template` | Shodan 검색 URL |
| `abuse_template` | AbuseIPDB 조회 URL 템플릿 |
| `note` | 특이사항 (결제방식, APT 관측 이력 등) |
| `source` | 출처 |

---

## 공급자 추가 시나리오

### 케이스 A: ASN을 아는 경우 (가장 빠름)
```bash
# 1. vps-providers.csv에 행 추가 (vendor, domain, asn 필수)
# 2. 파이프라인 실행 (ASN DB 다운로드 생략)
python3 scripts/pipeline.py --skip-fetch
```

### 케이스 B: ASN을 모르는 경우
```bash
# 1. 도메인으로 DNS → ASN 조회 시도
python3 scripts/update_providers.py --lookup <domain>

# 2. DNS가 CDN 뒤에 있으면 웹 검색으로 확인
#    - https://bgp.tools/search?q=<vendor_name>
#    - https://bgp.he.net/search?search[search]=<vendor_name>
#    - 웹 검색: "<vendor> ASN autonomous system"

# 3. vps-providers.csv에 행 추가 후 파이프라인 실행
python3 scripts/pipeline.py --skip-fetch
```

### 케이스 C: ASN DB 최신화 후 전체 재생성
```bash
# sapics에서 최신 asn-ipv4.csv 다운로드 + 전체 재생성
python3 scripts/pipeline.py
```

### 케이스 D: 특정 공급자만 재생성
```bash
python3 scripts/pipeline.py --skip-fetch --vendor BitLaunch
```

---

## IP 대역 메모 추가 (notes.csv)

특정 IP 대역에 APT 관측 이력 등 메모를 추가하려면:

```csv
# data/ip-ranges/notes.csv
vendor,cidr,note
BitLaunch,64.190.113.0/24,APT observed: Donot Team (APT-C-35) — 2025-09
Hostwinds,142.11.192.0/18,C2 IP 142.11.206.73 observed in Axios npm supply-chain attack (Mar 2026)
```

파이프라인 실행 시 자동으로 known-providers.csv에 병합됩니다.

---

## 스크립트 사용법 요약

```bash
# 전체 파이프라인
python3 scripts/pipeline.py

# ASN DB만 업데이트
python3 scripts/fetch_asn.py
python3 scripts/fetch_asn.py --check          # 업데이트 여부만 확인

# IP 대역 재생성
python3 scripts/generate_ranges.py
python3 scripts/generate_ranges.py --vendor Hostwinds

# Logpresso 쿼리 재생성
python3 scripts/generate_queries.py
python3 scripts/generate_queries.py --vendor BitLaunch

# 공급자 목록 검증/정렬
python3 scripts/update_providers.py
python3 scripts/update_providers.py --add     # 대화형 추가
python3 scripts/update_providers.py --lookup AS399629  # IP 대역 조회
```

---

## 공급자 선별 기준

다음 조건을 **하나 이상** 충족하는 서비스를 포함합니다:

1. **가상화폐 결제 지원** (Bitcoin, Monero, ETH 등)
2. **KYC 없음** (신원 확인 불요)
3. **DMCA/남용 신고 무시** (Bulletproof Hosting)
4. **Offshore 등록** (아이슬란드, 러시아, 루마니아, 네덜란드 등)
5. **실제 APT/랜섬웨어 인프라에서 관측됨**

---

## 리포트 추가

`reports/` 폴더에 마크다운 파일 추가. 파일명 형식: `<topic>-<YYYY>.md`
```
reports/lazarus-infrastructure-2025.md
reports/apt-c-35-donot-team-2025.md
```

---

## 주의사항

- 이 저장소는 **방어 목적(Threat Intelligence)** 으로만 사용됩니다.
- 공격적 활용, 실제 서비스 공격, 개인정보 침해에 사용하지 마십시오.
- IOC 데이터는 검증된 공개 출처만 참조합니다.
