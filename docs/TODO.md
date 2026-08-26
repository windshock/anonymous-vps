# Follow-up / Backlog

작업하며 남긴 후속 과제. 완료하면 체크하고, 새 항목은 근거와 함께 추가한다.

## 데이터 / 인벤토리
- [ ] **기존 candidate provider들의 자체 ASN 발굴** — NiceVPS(AS49447)처럼 누락된 소유
      ASN을 sapics DB(`data/asn-ipv4.csv`) org명 대조로 찾아 `asns.yml`에 연결하면
      provider-ranges + KR location-context 자동 편입. asns.yml 항목이 없는 provider부터
      점검(대부분 리셀러라 없을 가능성 높으니 확인만): Cloudzy, QloudHost, Ultahost,
      VikHost, VPSServer, Impreza.host, bitcoinvps.cloud/site, btc-vps.com, prv.to,
      theonionhost.com, hoststage.com, eldernode.com, vps-crypto.site, OrangeWebsite(상위망 Advania).
- [ ] **근거 기반 인벤토리 확장 계속** — 다른 각도(국가별 no-KYC, offshore 자체 ASN 보유)로
      추가 후보 수집. affiliate/SEO 껍데기 사이트(AnubizHost/Servury/XMR Host 등)는 계속 제외.
- [ ] **candidate → provider_verified 승격** — 각 service/payment/location 주장에
      claim-specific 공식 근거가 갖춰진 provider를 승격. 현재 verified: coin-host, evoxt, ghostvps.

## location context / 탐지
- [ ] **KR 외 국가로 일반화** — `generate_location_context.py`의 `COUNTRY`를 파라미터화하여
      필요 시 다른 대상국도 추출(현재 KR 고정).
- [ ] **registry국가 vs geo국가 불일치 자동 탐지** — GeoLite2 geo국가와 비교할 *레지스트리
      국가* 소스(RDAP netname 등)가 있어야 구현 가능. 소스 확보 후 mismatch 후보 산출.
- [ ] **IPv6 지원 검토** — sapics에 asn/country의 ipv6 변형이 있음.

## 검증 엄밀성 (정직한 한계 — 재검토 대상)
- [ ] **ASN 소유 확인을 RIR RDAP로 교차검증** — 현재는 sapics(GeoLite2) org명 대조만 사용.
      승격 전 rdap.db.ripe.net / rdap.arin.net 등으로 소유 재확인.
- [ ] **provider 근거를 결제/ToS 등 claim-specific 페이지로 보강** — 승격 근거 강화.

## 툴링 / 정리
- [ ] **legacy 스크립트 정리 결정** — `scripts/generate_ranges.py`(vps-providers.csv를 읽음)는
      현재 파이프라인 미사용(파이프라인은 `generate_provider_ranges.py` 사용). 삭제 또는
      "legacy" 명시. `scripts/update_providers.py` 사용 여부도 함께 점검.
- [ ] **provider당 복수 ASN 대역 반영** — `generate_provider_ranges.py`는
      `choose_primary_asn`로 provider당 ASN 1개만 사용 → AlexHost(AS200019/AS207636)처럼
      복수 ASN 보유 시 primary만 provider-ranges에 반영됨(location-context는 전부 사용).
      필요하면 owned/used ASN 전부의 대역을 내보내도록 개선.
- [ ] **주간 CI 동작 확인** — `update-asn.yml`이 이제 `country-ipv4.csv`도 받고
      `generated/context/`를 스테이징해야 함. 실제 실행 성공 확인.
- [ ] **테스트 DB 의존성 문서화** — 일부 통합 테스트(pipeline/generator dry-run)는
      gitignore된 대용량 DB가 있어야 실행됨(순수 코어 테스트는 오프라인). CONTRIBUTING에 명시.

## 메모
- ASN 이름불일치 경고 기준선은 현재 **7개**(NiceVPS 브랜드 vs 'Nice IT Services Group Inc.'
  법인명 추가). 브랜드≠법인명인 자체 ASN provider를 추가할 때마다 이 기준선을 갱신할 것.
- location context는 **DB-driven**(추적 ASN 대역 ∩ GeoLite2 국가 DB). 손으로 CIDR을 넣지 말 것.
