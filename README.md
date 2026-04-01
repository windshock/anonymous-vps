# 🕵️ Anonymous VPS Intelligence

익명성 보장 및 가상화폐 결제가 가능한 VPS 서비스를 큐레이션한 **Threat Intelligence** 저장소입니다.  
APT 그룹 및 랜섬웨어 조직이 실제로 악용한 인프라 데이터를 중심으로 정리합니다.

---

## 📦 데이터

### [`data/vps-providers.csv`](data/vps-providers.csv)
익명 VPS 공급자 목록 (상위 50개+). ASN, Shodan 검색 링크, 특이사항 포함.

| 컬럼 | 설명 |
|------|------|
| `vendor` | 서비스 이름 |
| `domain` | 공식 도메인 |
| `asn` | AS 번호 |
| `shodan_template` | Shodan 검색 URL |
| `abuse_template` | AbuseIPDB 조회 URL |
| `note` | 결제방식·익명성 특이사항 |

### [`data/asn-ipv4.csv`](data/asn-ipv4.csv)
전세계 ASN ↔ IPv4 대역 매핑 참조 데이터 (~40만 레코드).

---

## 📑 분석 리포트

| 파일 | 내용 |
|------|------|
| [apt-analysis-2020-2025.md](reports/apt-analysis-2020-2025.md) | APT 그룹(중국·러시아·중동)의 익명 VPS 악용 사례 (2020–2025) |
| [axios-supply-chain-2026.md](reports/axios-supply-chain-2026.md) | Axios npm 공급망 공격 심층 분석 (2026) |

---

## 🔍 공급자 선별 기준

- 가상화폐(BTC/XMR/ETH) 결제 지원
- KYC(신원확인) 없음
- DMCA/남용 신고 무시 (Bulletproof Hosting)
- Offshore 등록 (아이슬란드·러시아·루마니아 등)
- 실제 APT/랜섬웨어 인프라에서 관측됨

---

## ⚙️ 업데이트

```bash
# 공급자 목록 검증 및 정렬
python3 scripts/update_providers.py

# 특정 ASN의 IP 대역 조회
python3 scripts/update_providers.py --lookup AS399629
```

AI 에이전트를 통한 업데이트 방법은 [AGENT.md](AGENT.md)를 참조하세요.

---

## ⚠️ 면책 조항

본 저장소는 **방어적 보안 연구 및 Threat Intelligence** 목적으로만 제공됩니다.  
악의적 활용, 서비스 공격, 불법 행위에 사용하는 것을 엄격히 금지합니다.

---

## 📚 참고 출처

- [BushidoToken Blog — Investigating Anonymous VPS Services (2025)](https://blog.bushidotoken.net/2025/02/investigating-anonymous-vps-services.html)
- [Volexity — Operation EmailThief (2022)](https://www.volexity.com/blog/2022/02/03/operation-emailthief-active-exploitation-of-zero-day-xss-vulnerability-in-zimbra/)
- [own.security — Bulletproof Hosting Landscape](https://www.own.security/en/ressources/blog/50-shades-of-bulletproof-hosting-bph-landscape-on-russian-language-cybercrime-forums)
