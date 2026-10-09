# P2-VPN-01 (#37) — vpn-gw01 ↔ AWS Relay IPsec 구성 패키지

[#37](https://github.com/321Team/fds-project-baseline/issues/37)의 터널 구성·점검·원복 코드와 실행 runbook입니다. D21 Handoff(AWS EC2+EIP Libreswan Relay)와 #37 결정 코멘트를 구현합니다.
- SG tuple: 6041369929
- worker 서브넷: 6055390174
- Relay 세션·PSK 경계: 6010498202
- Harbor S1: 6074999671

**이 패키지는 코드 리뷰 대상이며 실행 GO가 아닙니다.** 운영 서버(vpn-gw01, Relay)에 적용하려면 리뷰된 SHA와 #37 작업창 승인이 필요합니다.

## 설계 요약

| 항목 | 값 | 근거 |
|---|---|---|
| 프로토콜 | IKEv2만, PSK(`authby=secret`) | D21 IKE semantic contract. 인증서 인증은 후속 승인 시 |
| 역할 | vpn-gw01 개시자(`auto=start`), Relay 응답자(`auto=add`, `right=%any`) | "On-Prem initiates", SG에 UDP egress 없음 |
| 신원 | vpn-gw01 `@fds-vpn-gw01`, Relay `@fds-aws-relay01` | 교육장 공인 IP(`121.160.42.93`↔`180.80.107.14`)가 교환 중에도 바뀌므로 주소가 아니라 IKE ID로 확인 |
| selector | `10.1.93.0/24 <-> 10.20.0.0/16` | Handoff |
| 제안 | IKE·ESP 모두 `aes256-sha2_256;modp2048`(ESP는 PFS) | 버전별 기본값 차이로 협상이 갈리지 않게 고정 |
| 수명 | vpn-gw01 IKE 7h / Child 50m, Relay 8h / 1h | vpn-gw01이 먼저 rekey(6037284573) |
| liveness | `dpddelay=30s`, `retransmit-timeout=120s` | 끊기면 vpn-gw01이 `auto=start`로 다시 세움 |
| NAT-T | `encapsulation=auto`, keepalive 기본 20초 | 양쪽 모두 NAT 뒤(교육장 NAT, EIP 1:1). Relay SG에 IKE egress가 없으므로 keepalive로 흐름 추적 유지 |
| 버전 차이 | 5.x `keyexchange=ikev2` / 4.x `ikev2=insist`, 명령도 `ipsec add` / `ipsec auto --add` | vpn-gw01은 Libreswan 5.4(Stream 10), Relay는 Stream 9의 4.x가 될 예정이라 문법 어댑터가 필요 |

### 포워딩은 fail-closed

- 영구 sysctl은 `ip_forward = 0`으로 둡니다. Relay는 bootstrap 파일 그대로, vpn-gw01은 `99-fds-p2-vpn-gw.conf`를 0으로 바꿉니다.
- `fds-p2-vpn-forward.service`가 FORWARD 허용표(`/etc/fds-p2-vpn/forward.nft`)를 올린 **뒤에만** `ip_forward=1`을 켭니다.
- 유닛이 실패하거나 멈추면 포워딩은 꺼진 채로 남습니다. 재부팅 때 허용표 없이 포워딩이 켜지는 순간이 없습니다.

### FORWARD 허용표 (`inet fds_p2_vpn`, firewalld 표와 별개)

| 호스트 | 방향 | 규칙 |
|---|---|---|
| Relay | VPC → On-Prem | **SA가 없으면 drop**(`rt ipsec missing`, 평문 우회 차단). established 응답은 허용. 새 연결은 `10.20.10.0/24 → 10.1.93.55:5432`만. 나머지는 drop |
| Relay | On-Prem → VPC | **복호화된 패킷만**(`meta ipsec`). established 응답만 허용하고, On-Prem에서 여는 새 연결은 drop |
| Relay | 그 밖 | `policy drop` |
| vpn-gw01 | VPC → On-Prem | 복호화된 패킷만. 새 연결은 `10.20.10.0/24 → 10.1.93.55:5432`만 |
| vpn-gw01 | On-Prem → VPC | SA가 없으면 drop(교육장 게이트웨이로 평문이 나가지 않게). 응답만 허용 |
| vpn-gw01 | `10.20.0.0/16`과 무관한 포워딩 | 판정하지 않음(기존 firewalld 동작 유지) |

- Harbor `10.1.93.54:443` 후보 규칙은 기본으로 꺼져 있습니다. `FDS_HARBOR=on`일 때만 렌더되며, 쓰는 조건은 #37 6074999671의 Gate 4개입니다.
- 어느 쪽에서도 SNAT·DNAT·masquerade를 하지 않습니다(no-inner-NAT).
- 목적지 `.55:5432` 한정은 이 표가 맡습니다. SG는 출발지 서브넷만 정하고, db01 방화벽·`pg_hba`가 마지막 겹입니다(#47).

## 파일

| 경로 | 설치 위치 |
|---|---|
| `conf/vpn-gw01.conf.tmpl`, `conf/relay.conf.tmpl` | `/etc/ipsec.d/fds-p2-vpn.conf` |
| `nft/*.nft.tmpl` | `/etc/fds-p2-vpn/forward.nft` |
| `systemd/fds-p2-vpn-forward.service` | `/etc/systemd/system/` |
| `p2vpn.sh` | 실행기(`check`·`render`·`psk`·`apply`·`up`·`status`·`probe`·`rollback`) |
| `tests/test_p2vpn.py` | 정적·렌더 시험, 가짜 호스트 흐름 시험(`tests/fakebin/`), CentOS Stream 9·10 실제 Libreswan·nftables 문법 시험 |

`/etc/ipsec.d/fds-p2-vpn.secrets`는 패키지에 없습니다. 세션에서 `psk`로만 만듭니다.

## 비밀 경계 — PSK

- **누가:** #37 Lead(이재환)가 만들고, 양쪽에 넣고, 교체합니다.
- **만들기:** 작업 PC에서 `openssl rand -base64 48`로 만듭니다. 64자, 따옴표·공백 없음. 파일·메모·채팅·Issue·증적에 저장하지 않습니다.
- **넣기:** 양쪽 세션에서 `sudo bash p2vpn.sh <role> psk`를 실행합니다. `read -s`라 화면·history에 남지 않고, 두 번 입력해 대조합니다. 결과 파일은 `root:root 0600`이고 SELinux 라벨을 복원합니다.
  - 입력값은 bash 내장 `printf`로만 파일에 씁니다. 프로세스 인자(argv)에 나타나지 않습니다.
  - 보고하는 것은 존재·소유자·권한뿐입니다. 파일 해시도 남기지 않습니다.
- **세션 기록:** Relay SSM 세션 문서는 로그를 끈 상태입니다(`SSM-SessionManagerRunShell`). PC 쪽 터미널 기록이나 `script --log-in/--log-io`도 쓰지 않습니다.
- **양쪽 일치 확인:** 별도 해시로 하지 않고, 터널 인증 성공(IKE_AUTH)으로 확인합니다. 불일치면 `AUTHENTICATION_FAILED`가 납니다.
- **교체·재구축:** 새 PSK를 만들어 양쪽에 `psk`를 다시 실행합니다(`rereadsecrets` 자동). Relay를 다시 만들면 PSK를 다시 넣어야 하므로, 재구축은 무인 복구로 세지 않습니다.
- **Relay 권한:** `AmazonSSMManagedInstanceCore`는 Parameter Store 읽기를 `*`로 허용합니다. 그래서 PSK를 Parameter Store에 두지 않습니다(6014247521 §2).

## 실행 순서 (실행자 이재환)

이권욱 리뷰 [6075917799](https://github.com/321Team/fds-project-baseline/issues/37#issuecomment-6075917799) R2에 따라 단계를 나눕니다.
- **SA 수립은 route 활성화를 위한 준비 증거일 뿐입니다.** DB TCP나 #37 전체 PASS로 표시하지 않습니다.
- 각 단계는 앞 단계 증적이 있어야 시작합니다.

### 단계 A — 선행 조건 (하나라도 없으면 시작하지 않음)
- #35 Stage-A 실제 자원 ID·Terraform source SHA, Relay 첫 부팅 readback(`TUNNEL=NOT_CONFIGURED`, `FORWARDING=DISABLED`, SSM Agent Online)
- EIP 값, Relay `libreswan` 정확한 NEVRA
- 이 패키지의 리뷰 SHA
- AWS route `activate_onprem_routes=false`
- vpn-gw01 쪽 작업창 승인과 공지

### 단계 B — 터널 수립 (route OFF)

| 순서 | 호스트 | 명령 | 통과 기준 |
|---|---|---|---|
| B0 | 둘 다 | 패키지 전달 → `sha256sum -c` | 리뷰 SHA의 파일 해시와 일치 |
| B1 | 둘 다 | `sudo bash p2vpn.sh <role> check` | 버전·sysctl·firewalld·기존 파일 기록. 기존 `fds-p2-vpn` 없음 |
| B2 | 둘 다 | `sudo bash p2vpn.sh <role> psk` | `secrets: present owner=root:root mode=600` |
| B3 | Relay | `sudo bash p2vpn.sh relay apply <RUN>` | `APPLY_OK`. UDP 500/4500 열림, 허용표 적재, `ip_forward=1`, conn 등록 |
| B4 | vpn-gw01 | `sudo RELAY_EIP=<EIP> bash p2vpn.sh vpn-gw01 apply <RUN>` | `APPLY_OK` |
| B5 | vpn-gw01 | `sudo bash p2vpn.sh vpn-gw01 up` | IKE SA와 Child SA 수립 |
| B6 | 둘 다 | `status`, T1·T2·T4·T5·T10 | 아래 시험표. 결과를 `tunnel_readiness_reference`로 묶음 |

### 단계 C — 승인 경로 준비 (별도 승인)
1. **#35:** `private_a → Relay ENI` route 활성화(`activate_onprem_routes=true`, `onprem_route_keys=["private_a"]`, 근거 = 단계 B 증적)
2. **#35:** `private_a` 임시 시험 인스턴스 생성(계획은 #37 코멘트, 비용 판정은 #34)
3. **DB Lead 사전 제한 시험 창(#11·#47):**
   - db01에 `10.20.10.0/24 → 5432` 허용, `pg_hba` 1줄, 복귀 경로 `10.20.0.0/16 via 10.1.93.51`
   - 시험 뒤 원복하고 readback합니다
   - 10/21 #47 A2를 앞당기거나 기존 P1 규칙을 넓히지 않습니다. 이 창이 없으면 T3·T6은 PENDING입니다

### 단계 D — 승인 경로 시험과 회귀
T3 → T6 → T3(복구 후) 순서로 진행하고, 이어서 T7~T9·T11, 마지막으로 정리(T12, 임시 인스턴스 삭제, DB 사전 규칙 원복과 readback)를 합니다. 끝난 뒤 AC·G4 판정 입력을 제출합니다.

### 공통 사항
- 패키지 전달:
  - vpn-gw01: 기존 방식(scp 또는 base64)
  - Relay: SSM 세션에 base64 붙여넣기. Relay는 사설 GitHub 저장소를 직접 받지 않습니다
- `apply`의 동작:
  - 그 서버의 실제 Libreswan으로 `ipsec addconn --checkconfig`, `nft -c`를 통과해야 설치합니다
  - 바뀌는 파일은 `/root/fds-p2-vpn/<RUN>/backup`에 백업합니다. 백업·검증(`cmp`)이 실패하면 호스트를 바꾸기 전에 멈춥니다
  - firewalld는 permanent만 바꾸고, 바뀐 것이 있을 때만 reload합니다
  - **최초 설치만 지원합니다.** 활성 RUN 표식(`/root/fds-p2-vpn/ACTIVE_RUN`)이나 기존 설치 파일·`fds_p2_vpn` 허용표가 있으면 새 RUN도 바꾸지 않고 거부합니다. 그 RUN을 `rollback`한 뒤 다시 합니다
  - 호스트를 바꾸기 시작한 뒤의 실패(파일 쓰기·설치·SELinux 라벨·유닛·conn 등록 등)는 `APPLY_OK` 없이 멈추고, 먼저 `ip_forward=0`을 readback으로 확인합니다. 그 RUN은 활성으로 남아 `rollback <RUN>`으로 정리합니다
  - 유닛은 시작 전(`ExecStartPre`) `ip_forward=0`을 걸고, 최초 시작 실패에도 `ExecStopPost`가 0을 확인한 뒤에만 허용표를 지웁니다

## 시험 (AC·TS 대응)

| ID | 단계 | 시험 | 방법 | 기대 | AC / TS |
|---|---|---|---|---|---|
| T1 | B | 터널 수립 | `status` 양쪽 | `fds-p2-vpn` IKE SA와 Child SA, UDP/4500 캡슐화, xfrm 정책 `10.1.93.0/24 <-> 10.20.0.0/16` | AC3 / TS06 |
| T2 | B | 터널 데이터 경로(진단) | Relay에서 `probe 10.1.93.51 22` | `CONNECTED`. Relay OUTPUT → vpn-gw01 INPUT 경로라 **승인 DB 경로 PASS가 아님** | AC3 진단 / TS06 |
| T3 | D | 승인 DB 경로 양성 | 임시 인스턴스(`10.20.10.0/24`의 실제 ENI)에서 `10.1.93.55:5432` 새 TCP | 연결 성공, Relay `to_onprem`·vpn-gw01 `from_vpc` 허용 카운터 증가, db01에서 출발지 관측 | AC4·5 / TS06 |
| T4 | B | 승인 밖 출발지 | Relay(`10.20.110.10`)에서 `probe 10.1.93.55 5432` | vpn-gw01 `from_vpc` 마지막 drop 카운터 증가와 함께 연결 실패 | AC6 / TS06 |
| T5 | B | 승인 밖 포트 | Relay에서 `probe 10.1.93.55 22` | 같은 drop 카운터 증가와 함께 연결 실패 | AC6 / TS06 |
| T6 | D | SA 없음 평문 차단 | `ipsec down` 뒤 T3와 같은 출발지·목적지 | 연결 실패, Relay `rt ipsec missing` 카운터 증가, Relay 외부 인터페이스에 `10.1.93.55` 평문 패킷 없음(`tcpdump`). 이어 `up` 뒤 T3 재통과 | AC6 / TS06 |
| T7 | D | 재시작 복구 | 양쪽 `systemctl restart ipsec` | vpn-gw01이 자동으로 다시 세움, T3 재통과 | AC7 / TS06 |
| T8 | D | 재부팅 복구 | Relay reboot, vpn-gw01 reboot, EC2 Stop→Start | 유닛이 허용표 적재 뒤 forward=1, 터널 자동 수립, T3 재통과 | AC7 / TS06 |
| T9 | D | rekey | `ipsec whack --rekey-ipsec --name fds-p2-vpn`(또는 32~41분 관측) | 새 Child SA, 끊김 없이 T3 재통과 | AC7 / TS06 |
| T10 | B | fail-closed | `systemctl stop fds-p2-vpn-forward` | `ip_forward=0`, 허용표 없음. 다시 start하면 복구 | AC6 / TS06 |
| T11 | D | 공인 IP 변동 | 작업창 동안 `status` 주기 기록 | SA 유지, 또는 DPD 뒤 자동 재수립. 관측값만 기록 | TS06(관측) |
| T12 | D | 원복 | 양쪽 `rollback <RUN>` → `check` | apply 전 상태와 같음 | 복구 계약 |

### 판정 규칙
- **연결 실패(TIMEOUT·REFUSED)만으로 차단 PASS를 내지 않습니다.** 같은 시도 전후의 해당 drop 카운터 증가와 묶어야 PASS입니다.
- 도구 오류, 권한 오류, route 부재, AWS SG에서 먼저 막힌 경우는 **판정 불가**입니다. SG 차단을 host FORWARD 차단 증거로 세지 않습니다.
- 양성은 새 TCP 연결 성공에 허용 카운터 증가와 db01 출발지 관측을 묶습니다.
- 모든 시험은 승인 경로가 열리는지(양성)와 막히는지(음성)를 짝으로 봅니다. 모두 막는 설정은 음성만 통과하기 때문입니다.
- 기록: 시작·종료 시각, rc, 양쪽 `status`, 카운터 전후 값
- MTU·MSS는 관측만 하고 AC로 보지 않습니다(6031888679)
- 컨테이너 문법 시험 PASS는 사용자 공간 문법 확인일 뿐입니다. 대상 kernel·XFRM·systemd·SELinux에서의 런타임 PASS가 아닙니다. 대상 서버의 `addconn --checkconfig`·`nft -c` rc는 `apply`가 따로 남깁니다.

### T3·T6 출발지 — private_a 임시 시험 인스턴스
리뷰 R1에 따라 #37 안에서 승인 경로를 증명합니다. 실제 ROSA 앱·NetworkPolicy·노드 출발지·거래 저장 검증은 #47에 그대로 남습니다.
- 인스턴스는 `private_a`의 실제 ENI를 씁니다. 공인 IP 없음, SSM 관리, NAT·Relay 출발지 대체나 주소 위조 없음.
- 자원 종류·수량·생성·삭제 일정은 #37 코멘트로 제출하고, IaC·IAM은 #35, 비용 판정은 #34에서 합니다.

## 원복

`sudo bash p2vpn.sh <role> rollback <RUN>`이 하는 일(활성 RUN과 다른 RUN이면 거부):
1. **먼저 `ip_forward=0`을 readback으로 확인.** 확인되지 않으면 허용표·유닛을 건드리지 않고 멈춤
2. conn이 등록돼 있을 때만 삭제하고, 삭제 뒤에도 남아 있으면 실패로 기록(이미 없음과 구분)
3. secrets `shred -u`, 설치 파일 삭제
4. 유닛 중지·해제, 허용표 삭제와 부재 확인
5. vpn-gw01의 sysctl 파일 복원(`cmp`)과 apply 전 런타임 `ip_forward` 값 복원(readback)
6. 이 RUN에서 추가한 firewalld 항목만 제거
7. apply 전에 꺼져 있던 `ipsec.service`는 다시 끄고 disable

단계마다 rc·readback을 확인합니다. 하나라도 실패하면 `ROLLBACK_DONE` 없이 `ROLLBACK_INCOMPLETE`와 실패 목록을 남기고 nonzero로 끝나며, 활성 RUN 표식을 유지합니다. 원인을 해소한 뒤 같은 RUN으로 다시 `rollback`할 수 있습니다. 모두 성공하면 표식을 지우고 `check`를 다시 출력합니다.

## 증적

`fds-project-evidence:evidence/P2-VPN-01/<RUN>/`에 다음을 둡니다.
- 양쪽 `check`·`status` 출력, `installed.sha256`, 시험 rc와 카운터, 원복 readback

secrets 내용·해시와 xfrm 키는 넣지 않습니다. `status`는 키를 가려서 출력합니다.

## 시험 실행

```bash
python3 -m unittest discover -s p2-vpn-01/tests -v
P2VPN_CONTAINER_IT=1 python3 -m unittest discover -s p2-vpn-01/tests -v
```

- 첫 번째 명령에는 Linux bash가 필요합니다. 여기에 **가짜 호스트 흐름 시험**이 포함됩니다.
  - 방식: `P2VPN_PREFIX`(시험 전용 경로 접두사, 운영에서는 비움)와 `tests/fakebin/`의 가짜 `firewall-cmd`·`ipsec`·`nft`·`systemctl`·`sysctl`·`ip`로 `psk`→`apply`→`status`→`rollback` 전체를 실행합니다.
  - 확인하는 것:
    - PSK가 출력·명령 인자에 나오지 않음, 0600, 줄 끝 CR 제거와 제어 문자 거부
    - 문법 검사를 통과하기 전에는 아무것도 바꾸지 않음
    - 유닛이 실패하면 포워딩이 꺼진 채로 남고 conn도 등록하지 않음(기존 런타임 `ip_forward=1`이어도 0으로 확인)
    - 백업 실패는 호스트 변경 전 중단, 설치 단계 실패는 `APPLY_OK` 없이 중단 후 rollback으로 원상 복구
    - 활성 RUN·기존 설치가 있으면 새 RUN apply를 무변경 거부, 다른 RUN의 rollback 거부
    - rollback 필수 단계(ip_forward 원복, firewalld 제거 등)가 실패하면 `ROLLBACK_INCOMPLETE`·nonzero이고 다시 실행할 수 있음. `ip_forward=0` 확인에 실패하면 허용표를 지우지 않음
    - 실패 주입: 가짜 명령에 `FAKE_FAIL`(glob)로 특정 호출만 rc1
    - firewalld는 바뀐 것이 있을 때만 reload
    - vpn-gw01 영구 sysctl은 0으로 바뀌고 원복하면 원래 값으로 돌아감
    - Libreswan 4.x는 `ipsec auto` 명령을 씀
    - 역할과 호스트 주소가 다르면 중단
    - `status`에서 xfrm 키를 가림
- 두 번째 명령에는 docker가 필요합니다. CentOS Stream 9·10 고정 digest에 배포판 `libreswan`·`nftables`를 설치하고 실제 문법을 검사합니다. 서버나 클러스터에는 접속하지 않습니다.
