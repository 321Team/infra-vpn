# P2-VPN-01 (#37) 네트워크 계약 — CIDR 대장 · Route 권위 · 재협상 절차

[#37](https://github.com/321Team/fds-project-baseline/issues/37) 핵심 요구사항 중 문서로 근거를 내는 3개를 다룹니다.

| 핵심 요구 | 이 문서 | 상태 |
|---|---|---|
| On-Prem/VPC CIDR 중복을 방지한다 | §1 | 확정값은 중복 없음(정적 시험). ROSA Pod/Service CIDR이 미정이라 **부분** |
| Route 전파와 Static Route의 권위 Source를 명시한다 | §2 | 명시 |
| Tunnel 재협상 절차를 기록한다 | §3 | 기록. 실제 rekey 관측(T9)은 NOT RUN |
| UDP 500/4500과 NAT-T 조건을 검증한다 | §4 | 설계만. 검증은 Runtime T1 |
| 필수 목적지·포트만 허용한다 | §4 | 설계만. 검증은 Runtime T3~T6 |

이 문서는 STATIC 문서입니다. 서버·AWS·클러스터에서 실행한 결과가 아니며, 핵심 요구 체크는 리뷰 뒤 Lead가 판단합니다. 값의 출처가 바뀌면 이 문서와 `tests/test_network_contract.py`를 같이 고칩니다.

## 1. CIDR 대장과 중복 검사

### 1.1 확정 대역

| 대역 | CIDR | 출처 | 터널 selector |
|---|---|---|---|
| On-Prem 물리 LAN(VMnet0 Bridged) | `10.1.93.0/24` | 정본 v3.1.21 §6.2.1·§6.4 | **On-Prem 쪽 selector** |
| 관리망(VMnet1 Host-only) | `10.250.10.0/24` | 정본 §6.4 | 아님 |
| VMware NAT(VMnet8) | `192.168.10.0/24` | 정본 §6.4(FDS VM NIC 연결 금지) | 아님 |
| P1 Kubernetes Pod | `10.244.0.0/16` | 정본 §6.5, P1-K8S-01 Calico IPv4 pool | 아님 |
| P1 Kubernetes Service | `10.96.0.0/12` | 정본 §6.5 | 아님 |
| AWS VPC | `10.20.0.0/16` | 정본 §6.5, infra-terraform `terraform/network` | **VPC 쪽 selector** |
| ├ `private_a`(ROSA worker·#37 probe) | `10.20.10.0/24` | infra-terraform `terraform/vpn` 입력 검증, infra-rosa#3 | VPC selector 안 |
| ├ `private_b` | `10.20.20.0/24` | 같은 곳 | VPC selector 안 |
| ├ `private_c` | `10.20.30.0/24` | 같은 곳 | VPC selector 안 |
| └ `public_transport_a`(Relay `10.20.110.10`) | `10.20.110.0/24` | 같은 곳 | VPC selector 안 |
| ROSA machine CIDR | `10.20.0.0/16` | infra-rosa#3·#4 확정(= VPC) | VPC selector와 같음 |

**중복 검사 결과:** 위 표의 최상위 대역 6개(`10.1.93.0/24`, `10.250.10.0/24`, `192.168.10.0/24`, `10.244.0.0/16`, `10.96.0.0/12`, `10.20.0.0/16`)는 서로 겹치지 않습니다. VPC 서브넷 4개는 VPC 안에 있고 서로 겹치지 않습니다. `tests/test_network_contract.py`가 Python `ipaddress`로 확인합니다.

터널 바깥 주소(IKE·ESP를 싣는 공인 주소)는 selector가 아니므로 위 표와 겹침 판정에서 뺍니다.
- 교육장 공인 IP: `121.160.42.93` ↔ `180.80.107.14`(교환 중에도 바뀜, README 설계 요약)
- Relay EIP: 미생성

### 1.2 미정 대역 — ROSA Pod / Service CIDR, host prefix

[infra-rosa#4](https://github.com/321Team/infra-rosa/issues/4) 생성 입력에서 "미정(#35 IaC 입력)"입니다. 생성 입력을 정할 때 다음을 지켜야 합니다.

1. §1.1의 확정 대역과 겹치지 않습니다. 특히 `10.1.93.0/24`, `10.250.10.0/24`, `10.20.0.0/16`과 겹치면 안 됩니다.
2. 터널 selector는 `10.1.93.0/24 <-> 10.20.0.0/16`뿐입니다. Pod·Service 주소가 출발지 그대로 On-Prem으로 나가면 터널에 들어가지 않고 막힙니다. 그래서 db01·Harbor가 보는 출발지는 worker 노드 주소(`private_a` `10.20.10.0/24`)여야 합니다. 이 조건은 infra-rosa `platform/netpol/TEST-PLAN.md` C1(Worker 노드 IP가 `10.20.0.0/16` 안)과 #47 A4에서 실제로 확인합니다.
3. ROSA 문서의 기본값(Pod `10.128.0.0/14`, Service `172.30.0.0/16`)을 쓰더라도 위 1번을 만족합니다(정적 시험에서 확인). 다만 기본값을 쓴다고 정해진 것은 아닙니다. 생성 뒤 `rosa describe cluster`의 실제 값으로 이 표를 갱신합니다(#35·#4).

## 2. Route 권위

**Route 전파는 없습니다.** D21 transport는 AWS EC2 Relay(Libreswan) 1대이고, VGW·TGW·BGP는 채택하지 않았습니다([#34 권위표](https://github.com/321Team/fds-project-baseline/issues/34), infra-terraform `docs/preflight-20261007/freeze-execution-gates-20261010.md`). 그래서 이 구간의 모든 경로는 static이고, 경로마다 권위 원본이 하나씩 있습니다.

| # | 경로 | 위치 | 권위 원본 | 변경 주체·승인 | 현재(2026-10-12) |
|---|---|---|---|---|---|
| R1 | public `0.0.0.0/0 → IGW`, private `0.0.0.0/0 → NAT` | VPC route table 4개 | infra-terraform `terraform/network` | #35 IaC 실행 Lead 이하영, network Apply GO | network Apply 진행 중(infra-terraform#11) |
| R2 | `private_a`: `10.1.93.0/24 → Relay ENI` | `private_a` route table | infra-terraform `terraform/vpn` `aws_route.onprem`(`activate_onprem_routes`, `onprem_route_keys=["private_a"]`만 허용) | #35 route 승인. 근거는 README 단계 B 증적 | OFF(`activate_onprem_routes=false`) |
| R3 | Relay가 남의 주소를 전달할 수 있음 | Relay ENI | `terraform/vpn` `source_dest_check = false` | #35 vpn Plan·GO | 미생성 |
| R4 | `10.1.93.0/24 <-> 10.20.0.0/16` 터널 정책 | 양쪽 커널 xfrm | 이 패키지 `conf/*.conf.tmpl`(`leftsubnet`/`rightsubnet`). Libreswan이 conn을 올릴 때 설치 | #37 이재환, README 단계 B | 미적용 |
| R5 | FORWARD 허용(복호화된 패킷만, 승인 목적지·포트만) | 양쪽 nft `inet fds_p2_vpn` | 이 패키지 `nft/*.nft.tmpl` + `fds-p2-vpn-forward.service` | #37 이재환 | 미적용 |
| R6 | db01 복귀 경로 `10.20.0.0/16 via 10.1.93.51` | db01 커널(사전 창은 runtime만, A2는 NM 영구) | infra-db `ops/p2-hyb01-rosa-db01`([infra-db#12](https://github.com/321Team/infra-db/pull/12)) | #47 이재환 실행, 창 GO 이권욱, DB 위험 확인 이하영 | 미적용(리뷰 중) |
| R7 | harbor01 복귀 경로(같은 값) | harbor01 | #13 Harbor 소관([#37 6074999671](https://github.com/321Team/fds-project-baseline/issues/37#issuecomment-6074999671)) | #13 | 미적용(D22 Final 아님) |
| R8 | 그 밖의 On-Prem 호스트 | 기본 게이트웨이 `10.1.93.254`(교육장) | 프로젝트 밖 | — | `10.20.0.0/16` 경로 없음. 응답하지 못하는 것이 **의도된 동작**(승인 목적지는 db01·harbor01뿐) |
| R9 | ROSA 내부 경로(Pod·Service·machine) | 클러스터 | ROSA 생성 입력(#4·#35) | #4·#35 | 미생성 |

운영 규칙:
- 위 원본 밖에서 경로를 손으로 추가하지 않습니다. 관측한 경로가 원본과 다르면 drift로 기록하고 해당 소관에 넘깁니다.
- 켜는 순서는 README 실행 순서(단계 A → B → C → D)를 따릅니다. 특히 R2는 R4(SA 수립) 증적이 있어야 승인 요청합니다.
- 끄는 방법은 원본마다 다릅니다.
  - R2: `activate_onprem_routes=false`로 #35 Plan·Apply
  - R4·R5: `p2vpn.sh <role> rollback <RUN>`
  - R6: `db01-rosa.sh pre-rollback|a2-rollback <같은 RUN>`
  - R7: #13 절차
- 한쪽만 꺼도 승인 경로는 닫힙니다. 다만 다른 쪽이 남아 있으면 상태가 원본과 어긋나므로, 각 원본의 readback으로 정리를 확인합니다.

## 3. Tunnel 재협상(rekey)·재수립 절차

### 3.1 설정값과 rekey 시점

`conf/*.conf.tmpl` 값입니다. rekey 시점은 `수명 − rekeymargin × (1~2)`입니다(`rekeyfuzz=100%`).

| 항목 | vpn-gw01(개시자) | Relay(응답자) |
|---|---|---|
| Child SA 수명 | `salifetime=50m` → rekey **32~41분** | `salifetime=1h` → rekey **42~51분** |
| IKE SA 수명 | `ikelifetime=7h` → rekey **6h42m~6h51m** | `ikelifetime=8h` → rekey **7h42m~7h51m** |
| `rekeymargin` / `rekeyfuzz` | `9m` / `100%` | `9m` / `100%` |
| liveness | `dpddelay=30s`, `retransmit-timeout=120s` | 같음 |
| 끊긴 뒤 | `auto=start`로 다시 세움 | `auto=add`(응답만) |

두 범위가 겹치지 않으므로 Child·IKE 모두 vpn-gw01이 먼저 rekey합니다(정적 시험에서 계산·확인).

### 3.2 정상 rekey 확인 (T9)

1. 시작 전 양쪽 `sudo bash p2vpn.sh <role> status`를 기록합니다. IKE·Child SA 번호(`#n`), `trafficstatus` 바이트를 남깁니다.
2. 자동 rekey를 기다리거나(vpn-gw01 기준 32~41분), vpn-gw01에서 수동으로 Child를 rekey합니다.
   - `sudo ipsec whack --rekey-ipsec --name fds-p2-vpn`
   - IKE: `sudo ipsec whack --rekey-ike --name fds-p2-vpn`
   - 대상 Libreswan(vpn-gw01 5.4, Relay 4.x)에서 이 옵션이 그대로인지는 B1 `check` 때 `ipsec whack --help`로 확인합니다(**NOT VERIFIED**). 다르면 그 버전의 명령으로 바꾸고 기록합니다.
   - 수동 rekey는 개시자(vpn-gw01)에서만 합니다. Relay는 응답자로 둡니다.
3. 다시 `status`를 기록합니다. 판정 기준은 다음 세 가지입니다.
   - 새 Child SA 번호가 생기고, 이전 SA는 만료됩니다.
   - 같은 `trafficstatus` 항목이 이어집니다.
   - T3(승인 DB 경로)가 끊김 없이 다시 통과합니다.

### 3.3 재협상 실패·끊김 대응

SA가 없을 때는 Relay의 `rt ipsec missing` drop과 fail-closed 포워딩 때문에 평문이 나가지 않습니다(T6·T10). 따라서 아래 절차는 **서비스 복구** 절차이며, 보안 경계를 회복하는 절차가 아닙니다.

| 순서 | 상황·확인 | 조치 |
|---|---|---|
| 1 | 양쪽 `status`, `journalctl -u ipsec --since <시각>` 수집 | 비밀이 없는 범위만 기록합니다(PSK·SPI 원문 금지. `status`는 SPI를 가림) |
| 2 | DPD timeout(120초) 뒤 vpn-gw01 자동 재수립 | `status`로 새 SA 확인 → T3 |
| 3 | 공인 IP 변동(교육장 두 주소) | IKE ID로 확인하므로 주소 변동만으로는 실패하지 않아야 합니다. 변동 시각·주소를 기록합니다(T11) |
| 4 | 자동 재수립 안 됨 | vpn-gw01 `sudo bash p2vpn.sh vpn-gw01 up` 1회 |
| 5 | 4번 실패 | 양쪽 `sudo systemctl restart ipsec`(T7 절차) → vpn-gw01이 다시 세우는지 확인 |
| 6 | 인증 실패(PSK 불일치·교체) | rekey로는 풀리지 않습니다. 양쪽 `p2vpn.sh <role> psk`로 같은 PSK를 비표시 입력 → `rereadsecrets` → `up`. PSK 원문은 Git·Issue·PR·채팅에 쓰지 않습니다 |
| 7 | 제안 불일치(`NO_PROPOSAL_CHOSEN` 등) | 양쪽 템플릿의 `ike`·`esp`가 같은지 `check`로 확인합니다. 템플릿 수정은 PR 리뷰 뒤에만 합니다 |
| 8 | 5~7로 복구되지 않음 | 서비스 영향을 판단합니다. R2가 ON이면 #35에 OFF를 요청하고, db01 사전 창 중이면 `pre-rollback`을 합니다. 터널은 `rollback <RUN>`으로 정리하고 원인을 기록합니다 |

모든 단계에서 시각, rc, 전후 `status`(SA 번호), 관련 카운터, T3 재통과 여부를 남깁니다.

## 4. 나머지 핵심 요구 — 설계만 있음

| 핵심 요구 | 설계 위치 | 검증(NOT RUN) |
|---|---|---|
| UDP 500/4500과 NAT-T | README 설계 요약(`encapsulation=auto`, 양쪽 NAT 뒤), Relay SG UDP 500/4500 ingress(infra-terraform `terraform/vpn`), Relay에서 IKE를 시작하지 않음 | T1: UDP/4500 캡슐화 SA |
| 필수 목적지·포트만 허용 | README FORWARD 허용표(`nft/*.nft.tmpl`), Relay SG, db01 rich rule(R6) | T3 양성 + T4·T5·T6 음성, 카운터 결속 판정 |

## 5. 시험

`python3 -m unittest discover -s p2-vpn-01/tests -v`에 포함됩니다(`tests/test_network_contract.py`). 확인하는 내용은 다음과 같습니다.
- §1.1 확정 대역끼리 겹치지 않음, VPC 서브넷이 VPC 안에서 서로 겹치지 않음, ROSA 문서 기본값 후보도 확정 대역과 겹치지 않음
- 양쪽 conn 템플릿의 selector가 §1.1의 On-Prem·VPC selector와 같음, 문서에 그 값이 있음
- 템플릿 수명·`rekeymargin`에서 계산한 rekey 범위가 §3.1 표와 같고, vpn-gw01 범위가 Relay 범위보다 항상 앞섬
