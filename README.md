# infra-vpn

P2-VPN-01([#37](https://github.com/321Team/fds-project-baseline/issues/37))의 **On-Prem vpn-gw01 ↔ AWS Relay IPsec 호스트 구성** 저장소입니다. 양쪽 게이트웨이의 conn, host FORWARD 허용표, 포워딩 유닛, PSK 입력 절차, 적용·점검·원복 스크립트, 시험과 runbook을 한 변경 단위로 관리합니다.

저장소 신설 근거: [#37 저장소 확인 요청 6075750728](https://github.com/321Team/fds-project-baseline/issues/37#issuecomment-6075750728) → [이권욱 A안 권고 6075917799](https://github.com/321Team/fds-project-baseline/issues/37#issuecomment-6075917799) §4.

## 범위

| 이 저장소 | 다른 곳(권위 유지) |
|---|---|
| vpn-gw01(`10.1.93.51`)·Relay(`10.20.110.10`) 호스트의 Libreswan conn, `/etc/ipsec.d` 설치, host FORWARD 허용표(nftables 전용 표), 포워딩 유닛, firewalld IKE 포트 | AWS VPC·subnet·SG·EIP·EC2·VPC route·IAM — `infra-terraform`, #35 |
| PSK 입력 절차(값은 저장하지 않음) | db01 방화벽·`pg_hba`·복귀 경로 — `infra-db`, #47·#11 |
| 터널 시험(양성·음성·복구)과 원복 runbook | Harbor 호스트 route·방화벽 — #13 |
|  | 증적 원본 — `fds-project-evidence:evidence/P2-VPN-01/` |

이 저장소로 코드를 모았다고 위 책임까지 옮기지 않습니다.

## 구조

| 경로 | 용도 |
|---|---|
| `docs/REVIEW_POLICY.md` | 리뷰·병합과 Lead 판단(중앙 정책 기준) |
| `.github/CODEOWNERS` | 리뷰 경로 안내. 독립 승인은 수동으로 확인 |
| `.github/PULL_REQUEST_TEMPLATE.md` | PR 기록 형식 |
| `p2-vpn-01/` | 터널 구성 패키지(후속 PR) |

## 역할

- Lead·병합 판단: 이재환(`supreme33-kr`)
- 코드 독립 리뷰: 이권욱(`GWONUK`)
- Relay AWS 자원·권한 입력: 이하영(#35·#38)

## 비밀정보

PSK·개인키·세션 키·토큰은 Git, Issue, PR, 증적, Terraform 변수·state, user_data, AMI에 넣지 않습니다. PSK는 작업 세션에서 `read -s`로만 입력하고, 존재·소유자·권한만 기록합니다(#37 6010498202).
