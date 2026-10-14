#!/usr/bin/env bash
# P2-VPN-01 (#37) — vpn-gw01 ↔ AWS Relay IPsec(IKEv2, PSK) 구성·점검·원복.
#
#   sudo bash p2vpn.sh <relay|vpn-gw01> check                 읽기 전용 상태
#   bash      p2vpn.sh <relay|vpn-gw01> render <outdir>        설정 파일만 만든다(서버 변경 없음, CI·리뷰용)
#   sudo bash p2vpn.sh <relay|vpn-gw01> psk <RUN>             PSK를 화면 표시 없이 입력해 secrets 파일(0600)에 저장
#   sudo bash p2vpn.sh <relay|vpn-gw01> psk-clean <RUN>       apply 전(state.env 없음)에 멈춘 RUN이 만든 secrets만 지움
#   sudo bash p2vpn.sh <relay|vpn-gw01> apply <RUN>            conn·FORWARD 허용표·fail-closed 유닛 설치, conn 등록
#   sudo bash p2vpn.sh vpn-gw01           up                   터널 개시(개시자만)
#   sudo bash p2vpn.sh <relay|vpn-gw01> status                SA·정책·허용표 카운터(키는 가림)
#   bash      p2vpn.sh <relay|vpn-gw01> probe <host> <port> [초]  TCP 연결 시도 rc
#   sudo bash p2vpn.sh <relay|vpn-gw01> rollback <RUN>         apply 전 상태로 되돌림
#
# 환경 변수: RELAY_EIP(vpn-gw01 render/apply 필수), FDS_HARBOR=on(D22 후보 Harbor 443 규칙, 기본 off),
#            LIBRESWAN_MAJOR(render 때 ipsec이 없으면 4 또는 5를 지정).
# PSK·키는 출력·파일 해시·로그에 남기지 않는다. secrets 파일은 존재·소유자·권한만 보고한다.
set -uo pipefail
set +x
umask 022

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROLE=${1:-}
CMD=${2:-}
CONN=fds-p2-vpn
# 시험 전용 경로 접두사. 운영에서는 설정하지 않는다(빈 값 = 실제 / 경로).
P=${P2VPN_PREFIX:-}
IPSEC_D=$P/etc/ipsec.d
CONF=$IPSEC_D/$CONN.conf
SECRETS=$IPSEC_D/$CONN.secrets
NFT_DIR=$P/etc/fds-p2-vpn
NFT_FILE=$NFT_DIR/forward.nft
UNIT=fds-p2-vpn-forward.service
UNIT_FILE=$P/etc/systemd/system/$UNIT
STATE_ROOT=$P/root/fds-p2-vpn
SYSCTL_D=$P/etc/sysctl.d
GW_SYSCTL=$SYSCTL_D/99-fds-p2-vpn-gw.conf
RELAY_SYSCTL=$SYSCTL_D/90-fds-relay-bootstrap.conf

die() { echo "STOP: $*" >&2; exit 1; }
say() { echo "== $*"; }

case "$ROLE" in
  relay|vpn-gw01) ;;
  *) die "역할은 relay 또는 vpn-gw01 (받은 값: '${ROLE}')" ;;
esac

libreswan_major() {
  if [ -n "${LIBRESWAN_MAJOR:-}" ]; then echo "$LIBRESWAN_MAJOR"; return; fi
  command -v ipsec > /dev/null 2>&1 || die "ipsec 명령 없음 — LIBRESWAN_MAJOR=4|5 지정 필요"
  ipsec --version 2>/dev/null | sed -n 's/.*Libreswan \(U\)\{0,1\}\([0-9][0-9]*\)\..*/\2/p' | head -1
}

ikev2_line() {
  case "${1:-}" in
    4) echo "ikev2=insist" ;;
    5) echo "keyexchange=ikev2" ;;
    *) die "지원하지 않는 Libreswan 주 버전: '$1' (4 또는 5)" ;;
  esac
}

# Libreswan 4.x는 ipsec auto --add, 5.x는 ipsec add(auto는 폐기 예정 경고).
ipsec_cmd() {
  local action=$1; shift
  if [ "$(libreswan_major)" = 4 ]; then
    case "$action" in
      add) ipsec auto --add "$@" ;; up) ipsec auto --up "$@" ;; delete) ipsec auto --delete "$@" ;;
      rereadsecrets) ipsec auto --rereadsecrets ;;
    esac
  else
    case "$action" in
      add) ipsec add "$@" ;; up) ipsec up "$@" ;; delete) ipsec delete "$@" ;;
      rereadsecrets) ipsec rereadsecrets ;;
    esac
  fi
}

harbor_rule() {
  if [ "${FDS_HARBOR:-off}" = on ]; then
    printf '\t\tip saddr 10.20.10.0/24 ip daddr 10.1.93.54 tcp dport 443 ct state new counter accept comment "worker -> harbor01 443 (D22 후보)"\n'
  else
    printf '\t\t# Harbor 443 후보 규칙 꺼짐(FDS_HARBOR=on일 때만, D22·#37 Gate 뒤)\n'
  fi
}

render() {
  local out=$1 major kw eip=""
  mkdir -p "$out"
  # $(...) 안의 die는 서브셸만 끝내므로 결과 코드를 다시 확인한다
  major=$(libreswan_major) || exit 1
  kw=$(ikev2_line "$major") || exit 1
  if [ "$ROLE" = vpn-gw01 ]; then
    eip=${RELAY_EIP:-}
    [[ "$eip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "RELAY_EIP 필요(IPv4): '${eip}'"
    case "$eip" in 10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) die "RELAY_EIP가 사설 주소: $eip" ;; esac
  fi
  sed -e "s|@@IKEV2@@|$kw|" -e "s|@@RELAY_EIP@@|$eip|" \
    "$HERE/conf/$ROLE.conf.tmpl" > "$out/$CONN.conf"
  grep -q '@@' "$out/$CONN.conf" && die "conn 자리표시자 남음"
  { printf 'config setup\n\n'; cat "$out/$CONN.conf"; } > "$out/ipsec-check.conf"
  harbor_rule > "$out/.harbor"
  # 첫 파일(Harbor 규칙)을 모았다가 자리표시자 줄과 바꾼다. 경로를 awk -v로 넘기지 않는다(역슬래시 해석).
  awk 'NR == FNR { h = h $0 "\n"; next } /^@@HARBOR@@$/ { printf "%s", h; next } { print }' \
    "$out/.harbor" "$HERE/nft/$ROLE.nft.tmpl" > "$out/forward.nft"
  rm -f "$out/.harbor"
  grep -q '@@' "$out/forward.nft" && die "nft 자리표시자 남음"
  cp "$HERE/systemd/$UNIT" "$out/$UNIT"
  echo "rendered role=$ROLE libreswan=$major harbor=${FDS_HARBOR:-off} eip=${eip:-n/a} -> $out"
}

need_root() { [ "$(id -u)" = 0 ] || die "root(sudo)로 실행"; }

identity_check() {
  case "$ROLE" in
    vpn-gw01) ip -4 -o addr show | grep -q ' 10\.1\.93\.51/' || die "이 호스트에 10.1.93.51 없음 — vpn-gw01이 아님" ;;
    relay) ip -4 -o addr show | grep -q ' 10\.20\.110\.10/' || die "이 호스트에 10.20.110.10 없음 — Relay가 아님" ;;
  esac
}

secrets_report() {
  if [ -e "$SECRETS" ]; then
    stat -c 'secrets: present owner=%U:%G mode=%a size>0=%s' "$SECRETS" | sed -E 's/size>0=[1-9][0-9]*/size>0=yes/; s/size>0=0/size>0=NO/'
  else
    echo "secrets: absent"
  fi
}

do_check() {
  say "identity / versions"
  hostname -s; ip -4 -o addr show | awk '{print $2, $4}'
  rpm -q libreswan nftables firewalld 2>/dev/null; uname -r
  echo "libreswan_major=$(libreswan_major 2>/dev/null || echo '?')"
  say "sysctl"
  sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter 2>/dev/null
  grep -H ip_forward "$SYSCTL_D"/*.conf 2>/dev/null || true
  say "firewalld"
  local zone; zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo '?')
  echo "default_zone=$zone forward=$(firewall-cmd --zone "$zone" --query-forward 2>/dev/null || echo '?')"
  firewall-cmd --zone "$zone" --list-ports 2>/dev/null | sed 's/^/ports: /'
  say "installed files (sha256)"
  for f in "$CONF" "$NFT_FILE" "$UNIT_FILE"; do [ -e "$f" ] && sha256sum "$f" || echo "absent $f"; done
  secrets_report
  say "unit / table"
  echo "unit=$(systemctl is-active "$UNIT" 2>/dev/null) enabled=$(systemctl is-enabled "$UNIT" 2>/dev/null)"
  nft list table inet fds_p2_vpn > /dev/null 2>&1 && echo "nft table: present" || echo "nft table: absent"
  say "ipsec"
  echo "ipsec.service=$(systemctl is-active ipsec 2>/dev/null) enabled=$(systemctl is-enabled ipsec 2>/dev/null)"
  ipsec trafficstatus 2>/dev/null | grep -F "$CONN" || echo "trafficstatus: $CONN 없음"
}

# psk가 만든 secrets의 소유 기록(비밀 없음: RUN·역할·경로·시각만). apply의 RUN 디렉터리와 겹치지 않는 곳에 둔다.
#  - receipts/<RUN>: RUN별 이력. cleaned_at이 붙은 RUN은 끝난 회차라 다시 쓰지 않는다(PR6 리뷰 C1).
#  - OWNER: 현재 secrets를 소유한 RUN 하나. psk가 파일을 쓰기 전에 기록하고, 파일 부재(와 필요한 rereadsecrets)
#    확인 뒤에만 지운다. apply·psk-clean·rollback·교체는 이 값과 RUN이 같을 때만 secrets를 다룬다.
PSK_RECEIPTS=$STATE_ROOT/psk-receipts
PSK_OWNER=$PSK_RECEIPTS/OWNER

psk_owner() { cat "$PSK_OWNER" 2>/dev/null; }
receipt_done() { [ -f "$1" ] && grep -q '^cleaned_at=' "$1"; }

# 소유 해제: 정리 완료를 기록한 뒤 OWNER를 지운다. 기록·해제 실패는 OWNER를 남긴 채 nonzero.
release_owner() {
  local run=$1 by=$2 receipt=$PSK_RECEIPTS/$1
  echo "cleaned_at=$(date -u +%FT%TZ) by=$by" >> "$receipt" || return 1
  rm -f "$PSK_OWNER" || return 1
  [ ! -e "$PSK_OWNER" ]
}

# ipsec.service 상태를 정상 응답과 조회 오류로 나눈다. 0=active, 1=inactive/failed(정상 응답), 2=확인 불가.
ipsec_svc_state() {
  local svc rc=0
  svc=$(systemctl is-active ipsec 2>/dev/null) || rc=$?
  case "$svc:$rc" in
    active:0) return 0 ;;
    inactive:3|failed:3) return 1 ;;
    *) IPSEC_SVC="$svc rc=$rc"; return 2 ;;
  esac
}

do_psk() {
  need_root; identity_check
  local run=${1:-}; [[ "$run" =~ ^[0-9]{8}T[0-9]{4}$ ]] || die "RUN 형식 YYYYMMDDTHHMM 필요"
  local receipt=$PSK_RECEIPTS/$run active="" owner
  receipt_done "$receipt" && die "RUN $run 은 이미 정리됨 — 새 RUN 사용(끝난 회차 기록을 다시 쓰지 않음)"
  owner=$(psk_owner)
  [ -e "$ACTIVE" ] && active=$(cat "$ACTIVE" 2>/dev/null)
  if [ -n "$active" ]; then
    # 설치가 살아 있으면 그 RUN의 교체만 허용한다.
    [ "$active" = "$run" ] || die "활성 RUN은 $active — 다른 RUN($run)으로 secrets를 바꾸지 않음"
    [ "$owner" = "$run" ] || die "secrets 소유 RUN('$owner')이 활성 RUN($run)과 다름 — 수동 확인"
  elif [ -n "$owner" ]; then
    # 설치 전: 이 RUN이 소유한 secrets만 다시 쓴다(부분 실패 뒤 재시도 포함).
    [ "$owner" = "$run" ] || die "현재 secrets 소유 RUN은 $owner — 'psk-clean $owner' 뒤 새 RUN으로"
  elif [ -e "$SECRETS" ]; then
    die "기존 secrets가 있고 이 RUN($run)의 생성 기록이 없음 — 덮어쓰지 않음(소유 확인 필요)"
  fi
  local a b tmp
  read -r -s -p "PSK 입력(표시 안 됨): " a; echo
  read -r -s -p "PSK 다시 입력: " b; echo
  # 붙여넣기에 섞인 줄 끝 CR은 지운다. 그 밖의 제어 문자가 있으면 거부한다.
  a=${a%$'\r'}; b=${b%$'\r'}
  [ "$a" = "$b" ] || { unset a b; die "두 입력이 다름"; }
  unset b
  [[ "$a" =~ [[:cntrl:]] ]] && { unset a; die "PSK에 제어 문자 금지"; }
  [ "${#a}" -ge 32 ] || { unset a; die "PSK는 32자 이상"; }
  case "$a" in *'"'*|*' '*) unset a; die "PSK에 따옴표·공백 금지(base64 권장)" ;; esac
  # 파일을 쓰기 전에 소유를 기록한다. 이후 어느 단계에서 멈춰도 이 RUN으로 정리(psk-clean)할 수 있다.
  if [ ! -f "$receipt" ] || [ "$owner" != "$run" ]; then
    { mkdir -p "$PSK_RECEIPTS" && chmod 700 "$STATE_ROOT" "$PSK_RECEIPTS"; } ||
      { unset a; die "secrets 기록 디렉터리 생성 실패 — secrets 변경 없음"; }
    if [ ! -f "$receipt" ]; then
      { echo "run=$run"; echo "role=$ROLE"; echo "path=$SECRETS"; echo "started_at=$(date -u +%FT%TZ)"; } > "$receipt" ||
        { unset a; die "secrets 생성 기록 실패 — secrets 변경 없음"; }
    fi
    echo "$run" > "$PSK_OWNER" && [ "$(psk_owner)" = "$run" ] ||
      { unset a; die "secrets 소유 표식 기록 실패 — secrets 변경 없음"; }
  fi
  umask 077
  tmp=$(mktemp "$IPSEC_D/.$CONN.secrets.XXXXXX") || { unset a; die "임시 파일 생성 실패 — 소유 $run 유지, 'psk-clean $run'으로 정리 가능"; }
  # 쓰기·권한·교체 중 하나라도 실패하면 임시 파일을 지우고 기존 secrets는 그대로 둔다.
  if ! printf '@fds-vpn-gw01 @fds-aws-relay01 : PSK "%s"\n' "$a" > "$tmp"; then
    unset a; rm -f "$tmp"; die "secrets 임시 파일 쓰기 실패 — 기존 secrets 유지, 소유 $run 유지"
  fi
  unset a
  if ! { chown root:root "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$SECRETS"; }; then
    rm -f "$tmp"; die "secrets 저장 실패 — 기존 secrets 유지, 소유 $run 유지('psk-clean $run'으로 정리 가능)"
  fi
  if command -v restorecon > /dev/null 2>&1; then restorecon "$SECRETS" || die "secrets SELinux 라벨 복원 실패"; fi
  echo "written_at=$(date -u +%FT%TZ)" >> "$receipt" || echo "WARN: 생성 시각 기록 실패(소유 $run 유지)" >&2
  secrets_report
  echo "psk_receipt=$receipt owner=$run"
  if systemctl is-active --quiet ipsec; then ipsec_cmd rereadsecrets && echo "rereadsecrets rc=0"; fi
}

# apply 전에 멈춘 RUN 정리: B2(psk)만 했거나 apply가 사전 검사에서 멈춰 state.env·ACTIVE가 없을 때.
# 현재 secrets 소유 RUN(OWNER)과 같은 RUN만 지운다. 설치 흔적·조회 오류가 하나라도 있으면 멈춘다.
do_psk_clean() {
  need_root; identity_check
  local run=${1:-}; [[ "$run" =~ ^[0-9]{8}T[0-9]{4}$ ]] || die "RUN 형식 YYYYMMDDTHHMM 필요"
  local receipt=$PSK_RECEIPTS/$run owner
  [ -e "$ACTIVE" ] && die "활성 RUN 있음($(cat "$ACTIVE" 2>/dev/null)) — 'rollback'을 사용"
  [ -e "$STATE_ROOT/$run/state.env" ] && die "이 RUN은 apply 기록(state.env)이 있음 — 'rollback $run'을 사용"
  [ -f "$receipt" ] || die "이 RUN($run)의 secrets 생성 기록 없음 — 지우지 않음(수동 판단)"
  receipt_done "$receipt" && die "RUN $run 은 이미 정리됨 — 현재 secrets를 변경하지 않음(소유 RUN 확인)"
  owner=$(psk_owner)
  [ "$owner" = "$run" ] || die "현재 secrets 소유 RUN은 '${owner:-없음}' — RUN $run 으로 지우지 않음"
  for f in "$CONF" "$NFT_FILE" "$UNIT_FILE"; do
    [ -e "$f" ] && die "설치 파일이 있음($f) — psk-clean 대상 아님, 소유 RUN rollback 확인"
  done
  nft_table_state
  case $? in
    0) die "fds_p2_vpn table 있음 — psk-clean 대상 아님, 소유 RUN rollback 확인" ;;
    1) : ;;
    *) die "nft 목록 조회 실패 — 부재로 취급하지 않고 중단(secrets 보존)" ;;
  esac
  unit_state || die "포워딩 유닛 상태 조회 실패 — 중단(secrets 보존)"
  unit_stopped || die "포워딩 유닛이 남아 있음($UNIT_ACT/$UNIT_EN) — psk-clean 대상 아님"
  # ipsec 상태: 정상 응답(active/inactive/failed)만 진행한다. 조회 오류·빈값·전환 중이면 지우지 않는다(PR6 리뷰 C2).
  local svc_rc conn_rc
  ipsec_svc_state; svc_rc=$?
  case "$svc_rc" in
    0)
      conn_loaded; conn_rc=$?
      case "$conn_rc" in
        1) : ;;
        0) die "conn $CONN 이 적재돼 있음 — psk-clean 대상 아님, 소유 RUN rollback 확인" ;;
        *) die "conn 조회 실패 — 중단(secrets 보존)" ;;
      esac ;;
    1) : ;;
    *) die "ipsec 상태 확인 불가($IPSEC_SVC) — 중단(secrets 보존)" ;;
  esac
  if [ -e "$SECRETS" ]; then
    shred -u "$SECRETS" 2>/dev/null || rm -f "$SECRETS" || die "secrets 삭제 실패 — 소유 $run 유지"
  fi
  [ -e "$SECRETS" ] && die "secrets가 남아 있음 — 소유 $run 유지"
  echo "secrets: absent"
  # ipsec이 떠 있으면 pluto가 읽어 둔 키도 다시 읽혀 비운다. 실패하면 소유를 유지해 같은 RUN으로 재시도한다.
  if [ "$svc_rc" = 0 ]; then
    ipsec_cmd rereadsecrets || die "secrets 파일은 삭제됨, rereadsecrets 실패 — 소유 $run 유지, 같은 RUN으로 재시도"
    echo "rereadsecrets rc=0"
  fi
  release_owner "$run" psk-clean || die "정리 기록·소유 해제 실패(secrets는 삭제됨) — 수동 확인"
  echo "PSK_CLEAN_DONE role=$ROLE run=$run"
}

# 런타임 포워딩을 끄고 readback으로 0을 확인한다.
forward_off() {
  sysctl -w net.ipv4.ip_forward=0 > /dev/null || return 1
  [ "$(sysctl -n net.ipv4.ip_forward)" = 0 ]
}
# apply 도중 실패: 포워딩을 먼저 끄고(확인) 멈춘다. 이 RUN은 ACTIVE_RUN으로 남아 rollback으로 정리한다.
apply_fail() {
  if forward_off; then die "$* — ip_forward=0 확인. 'rollback $APPLY_RUN'으로 정리"
  else die "$* — ip_forward=0 설정/확인도 실패. 즉시 수동 확인"; fi
}
ACTIVE=$STATE_ROOT/ACTIVE_RUN

# firewalld permanent 조회: 0=있음, 1=없음, 2=조회 오류(없음으로 보지 않는다). 호출한 함수의 $zone을 쓴다.
fw_has() {
  firewall-cmd --permanent --zone "$zone" "$@" > /dev/null 2>&1
  case $? in 0) return 0 ;; 1) return 1 ;; *) return 2 ;; esac
}
fw_yesno() {
  fw_has "$@"
  case $? in 0) echo yes ;; 1) echo no ;; *) echo ERR ;; esac
}

# 포워딩 유닛 상태를 조회로 읽는다(파일 존재로 판단하지 않는다).
# 결과: UNIT_ACT(active|inactive|...), UNIT_EN(enabled|disabled|not-found|...). 조회 불가면 rc2.
unit_state() {
  UNIT_ACT=$(systemctl is-active "$UNIT" 2>/dev/null)
  UNIT_EN=$(systemctl is-enabled "$UNIT" 2>/dev/null)
  if [ -z "$UNIT_EN" ] && [ ! -e "$UNIT_FILE" ]; then UNIT_EN=not-found; fi
  case "$UNIT_ACT" in active|activating|deactivating|reloading|inactive|failed|unknown) ;; *) return 2 ;; esac
  case "$UNIT_EN" in enabled|enabled-runtime|disabled|static|masked|linked|linked-runtime|indirect|generated|not-found) ;; *) return 2 ;; esac
  return 0
}
unit_stopped() {
  case "$UNIT_ACT" in inactive|failed|unknown) ;; *) return 1 ;; esac
  case "$UNIT_EN" in enabled|enabled-runtime) return 1 ;; esac
  return 0
}

# 표 목록 조회가 성공한 뒤에만 있음·없음을 판정한다(PR #11 6163219831 R1).
# 0=있음, 1=조회 성공·없음, 2=조회 오류(없음으로 보지 않는다)
nft_table_state() {
  local tables
  tables=$(nft list tables) || return 2
  if grep -qx 'table inet fds_p2_vpn' <<< "$tables"; then return 0; fi
  return 1
}

do_apply() {
  need_root; identity_check
  local run=${1:-}; [[ "$run" =~ ^[0-9]{8}T[0-9]{4}$ ]] || die "RUN 형식 YYYYMMDDTHHMM 필요"
  local dir=$STATE_ROOT/$run; [ -e "$dir" ] && die "$dir 이미 있음 — 새 RUN 사용"
  [ -s "$SECRETS" ] || die "secrets 없음 — 먼저 psk"
  # 최초 설치만 지원한다. 이전 RUN이 남아 있으면 덮어쓰지 않는다(그 RUN을 rollback·확인한 뒤 다시).
  [ -e "$ACTIVE" ] && die "활성 RUN 있음($(cat "$ACTIVE" 2>/dev/null)) — 그 RUN rollback 후 재시도"
  for f in "$CONF" "$NFT_FILE" "$UNIT_FILE"; do
    [ -e "$f" ] && die "기존 설치 존재 — 소유 RUN 원복·확인 후 재시도: $f"
  done
  nft_table_state
  case $? in
    0) die "기존 fds_p2_vpn table 존재 — 소유 RUN 확인 필요" ;;
    1) : ;;
    *) die "nft 목록 조회 실패 — 부재로 취급하지 않고 설치 중단" ;;
  esac
  # 파일이 없어도 이전 RUN의 유닛이 살아 있거나 부팅 링크가 남아 있으면 덮어쓰지 않는다.
  unit_state || die "포워딩 유닛 상태 조회 실패('$UNIT_ACT'/'$UNIT_EN') — 설치 중단"
  unit_stopped || die "포워딩 유닛이 남아 있음($UNIT_ACT/$UNIT_EN) — 소유 RUN 원복·확인 후 재시도"
  # secrets는 이 RUN이 psk로 만든 것이어야 한다(PR6 리뷰 C1: 실행·정리의 RUN 결속).
  [ "$(psk_owner)" = "$run" ] || die "secrets 소유 RUN('$(psk_owner)')이 apply RUN($run)과 다름 — 'psk $run'으로 만든 secrets만 사용"
  mkdir -p "$dir/backup" "$dir/staged" || die "state 디렉터리 생성 실패"
  chmod 700 "$STATE_ROOT" "$dir" || die "state 디렉터리 권한 설정 실패"
  render "$dir/staged" || die "render 실패"
  ipsec addconn --checkconfig --config "$dir/staged/ipsec-check.conf" || die "conn 문법 검사 실패"
  nft -c -f "$dir/staged/forward.nft" || die "nft 문법 검사 실패"

  say "backup (실패하면 호스트를 바꾸기 전에 멈춘다)"
  for f in "$CONF" "$NFT_FILE" "$UNIT_FILE" "$GW_SYSCTL" "$RELAY_SYSCTL"; do
    if [ -e "$f" ]; then
      cp -a "$f" "$dir/backup/" || die "백업 실패 — 설치 중단: $f"
      cmp -s "$f" "$dir/backup/$(basename "$f")" || die "백업 검증 실패 — 설치 중단: $f"
      echo "backup $f"
    fi
  done
  local zone fwd ipsec_active ipsec_enabled
  zone=$(firewall-cmd --get-default-zone) || die "firewalld 조회 실패"
  fwd=$(sysctl -n net.ipv4.ip_forward) || die "ip_forward 조회 실패"
  [[ "$fwd" =~ ^[01]$ ]] || die "ip_forward 값 이상: '$fwd'"
  ipsec_active=$(systemctl is-active ipsec 2>/dev/null); ipsec_enabled=$(systemctl is-enabled ipsec 2>/dev/null)
  # firewalld 원래 상태: 조회 오류를 "없음"으로 기록하면 rollback이 원래 있던 항목을 지우므로 여기서 멈춘다.
  local zf p500 p4500
  zf=$(fw_yesno --query-forward); p500=$(fw_yesno --query-port 500/udp); p4500=$(fw_yesno --query-port 4500/udp)
  case "$zf $p500 $p4500" in *ERR*) die "firewalld 원래 상태 조회 실패(forward=$zf 500=$p500 4500=$p4500) — 설치 중단" ;; esac
  {
    echo "zone=$zone"
    echo "ip_forward_runtime=$fwd"
    echo "zone_forward=$zf"
    echo "port_500=$p500"
    echo "port_4500=$p4500"
    echo "ipsec_active=${ipsec_active:-unknown}"
    echo "ipsec_enabled=${ipsec_enabled:-unknown}"
  } > "$dir/state.env" || die "state.env 기록 실패 — 설치 중단"
  grep -q "^ip_forward_runtime=$fwd\$" "$dir/state.env" || die "state.env 확인 실패 — 설치 중단"
  cat "$dir/state.env"
  # 여기부터 호스트를 바꾼다. 실패해도 이 RUN이 활성으로 남아 rollback 대상이 된다.
  echo "$run" > "$ACTIVE" || die "활성 RUN 표식 기록 실패 — 설치 중단"
  APPLY_RUN=$run

  say "persistent ip_forward=0 (fail-closed; 유닛이 허용표 적재 뒤에만 켠다)"
  if [ "$ROLE" = vpn-gw01 ]; then
    [ -e "$GW_SYSCTL" ] || apply_fail "$GW_SYSCTL 없음"
    sed -i -E 's/^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=.*/net.ipv4.ip_forward = 0/' "$GW_SYSCTL" || apply_fail "$GW_SYSCTL 수정 실패"
    grep -q '^net.ipv4.ip_forward = 0$' "$GW_SYSCTL" || apply_fail "$GW_SYSCTL ip_forward=0 반영 실패"
  else
    grep -Eq '^net\.ipv4\.ip_forward *= *0$' "$RELAY_SYSCTL" || apply_fail "$RELAY_SYSCTL 이 ip_forward=0 이 아님"
  fi

  say "firewalld (permanent만 바꾸고, 바꾼 것이 있을 때만 reload)"
  local changed=no
  if [ "$ROLE" = relay ]; then
    for p in 500/udp 4500/udp; do
      fw_has --query-port "$p"
      case $? in
        0) ;;
        1) firewall-cmd --permanent --zone "$zone" --add-port "$p" > /dev/null || apply_fail "port $p 추가 실패"
           changed=yes ;;
        *) apply_fail "port $p 조회 실패" ;;
      esac
    done
  fi
  fw_has --query-forward
  case $? in
    0) ;;
    1) firewall-cmd --permanent --zone "$zone" --add-forward > /dev/null || apply_fail "zone forward 허용 실패"
       changed=yes ;;
    *) apply_fail "zone forward 조회 실패" ;;
  esac
  echo "firewalld_changed=$changed" >> "$dir/state.env" || apply_fail "state.env 갱신 실패"
  if [ "$changed" = yes ]; then firewall-cmd --reload > /dev/null || apply_fail "firewalld reload 실패"; fi
  echo "firewalld_changed=$changed"

  say "install"
  install -d -m 0755 "$NFT_DIR" || apply_fail "$NFT_DIR 생성 실패"
  install -m 0644 "$dir/staged/forward.nft" "$NFT_FILE" || apply_fail "$NFT_FILE 설치 실패"
  install -m 0644 "$dir/staged/$CONN.conf" "$CONF" || apply_fail "$CONF 설치 실패"
  install -m 0644 "$dir/staged/$UNIT" "$UNIT_FILE" || apply_fail "$UNIT_FILE 설치 실패"
  if command -v restorecon > /dev/null 2>&1; then
    restorecon "$NFT_FILE" "$CONF" "$UNIT_FILE" || apply_fail "SELinux 라벨 복원 실패"
  fi
  systemctl daemon-reload || apply_fail "daemon-reload 실패"
  systemctl enable "$UNIT" > /dev/null 2>&1 || apply_fail "유닛 enable 실패"
  systemctl restart "$UNIT" || apply_fail "유닛 시작 실패 — 포워딩은 꺼진 채로 둔다"
  nft list table inet fds_p2_vpn > /dev/null || apply_fail "허용표 없음"
  [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || apply_fail "ip_forward가 켜지지 않음"

  say "ipsec"
  systemctl enable --now ipsec > /dev/null 2>&1 || apply_fail "ipsec.service 시작 실패"
  ipsec_cmd rereadsecrets || apply_fail "rereadsecrets 실패"
  ipsec_cmd add "$CONN" || apply_fail "conn 등록 실패"
  sha256sum "$CONF" "$NFT_FILE" "$UNIT_FILE" > "$dir/installed.sha256" || apply_fail "설치 해시 기록 실패"
  cat "$dir/installed.sha256"
  secrets_report
  echo "APPLY_OK role=$ROLE run=$run state=$dir"
}

do_status() {
  need_root
  ipsec trafficstatus 2>/dev/null | grep -F "$CONN" || echo "trafficstatus: $CONN 없음"
  ipsec showstates 2>/dev/null | grep -F "$CONN" | sed -E 's/0x[0-9a-fA-F]{16,}/<redacted>/g' | tail -n 20
  say "xfrm policy"; ip xfrm policy | grep -E '^(src|\s+dir|\s+tmpl)' || true
  say "xfrm state (키 가림)"; ip xfrm state | sed -E 's/0x[0-9a-fA-F]{8,}/<redacted>/g' | grep -E '^src|proto|mode|encap|replay' || true
  say "forward table"; nft list table inet fds_p2_vpn 2>/dev/null || echo "absent"
  echo "ip_forward=$(sysctl -n net.ipv4.ip_forward) unit=$(systemctl is-active "$UNIT")"
}

do_probe() {
  local host=${1:?host} port=${2:?port} t=${3:-5}
  timeout "$t" bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null
  local rc=$?
  case "$rc" in
    0) verdict=CONNECTED ;; 124) verdict=TIMEOUT ;; 1) verdict=REFUSED_OR_UNREACHABLE ;; *) verdict=ERROR ;;
  esac
  echo "probe $host:$port t=${t}s rc=$rc verdict=$verdict"
  return 0
}

# conn 등록 상태: 0=등록됨, 1=조회 성공·없음, 2=조회 실패(부재로 보지 않는다)
conn_loaded() {
  local out
  out=$(ipsec status 2>/dev/null) || return 2
  grep -qF "\"$CONN\"" <<< "$out"
}

do_rollback() {
  need_root; identity_check
  local run=${1:-}; local dir=$STATE_ROOT/$run
  [ -n "$run" ] && [ -f "$dir/state.env" ] || die "$dir/state.env 없음"
  if [ -e "$ACTIVE" ] && [ "$(cat "$ACTIVE")" != "$run" ]; then
    die "활성 RUN은 $(cat "$ACTIVE") — 다른 RUN($run)으로 원복하지 않음"
  fi
  # shellcheck disable=SC1091
  . "$dir/state.env"
  local failed=() b
  fail() { failed+=("$*"); echo "FAIL: $*" >&2; }

  # 1) 통제를 걷기 전에 포워딩부터 끈다. 0이 확인되지 않으면 허용표·유닛을 건드리지 않고 멈춘다.
  forward_off || die "ip_forward=0 설정/확인 실패 — 허용표를 그대로 두고 중단(재시도 가능)"
  echo "== ip_forward=0 확인"
  nft_table_state
  case $? in
    0|1) : ;;
    *) die "nft 목록 조회 실패 — ip_forward=0·통제·ACTIVE 보존, 같은 RUN으로 재시도" ;;
  esac

  # 2) conn: 등록·없음·조회 실패를 구분한다. 삭제·부재 확인·조회가 실패하면 ip_forward=0과
  #    허용표·유닛을 그대로 둔 채 멈춘다(원인 해소 뒤 같은 RUN으로 다시 rollback).
  local svc conn_rc
  svc=$(systemctl is-active ipsec 2>/dev/null) || true
  case "$svc" in
    active)
      conn_loaded; conn_rc=$?
      case "$conn_rc" in
        0)
          ipsec_cmd delete "$CONN" || die "conn 삭제 실패 — ip_forward=0·통제 보존, 같은 RUN으로 재시도"
          conn_loaded; conn_rc=$?
          [ "$conn_rc" = 1 ] || die "conn 부재 확인 실패(rc=$conn_rc) — ip_forward=0·통제 보존, 같은 RUN으로 재시도"
          echo "conn: 삭제·부재 확인" ;;
        1) echo "conn: 등록 없음(조회 확인)" ;;
        *) die "conn 조회 실패 — ip_forward=0·통제 보존, 같은 RUN으로 재시도" ;;
      esac ;;
    inactive|failed) echo "ipsec.service: $svc — conn 적재 없음" ;;
    *) die "ipsec.service 상태 불확실('$svc') — ip_forward=0·통제 보존, 같은 RUN으로 재시도" ;;
  esac
  if [ -e "$CONF" ]; then rm -f "$CONF" || fail "$CONF 삭제 실패"; fi
  if [ -e "$SECRETS" ]; then shred -u "$SECRETS" 2>/dev/null || rm -f "$SECRETS" || fail "secrets 삭제 실패"; fi
  [ -e "$SECRETS" ] && fail "secrets가 남아 있음"

  # 3) 유닛: 파일 존재가 아니라 조회 상태로 판단한다. 중지·해제나 그 확인이 실패하면 유닛·허용표 파일과
  #    ACTIVE를 그대로 두고 멈춘다(파일을 지우면 같은 RUN 재시도가 중지 단계를 건너뛰게 된다).
  unit_state || die "유닛 상태 조회 실패('$UNIT_ACT'/'$UNIT_EN') — ip_forward=0, 유닛·허용표 파일·ACTIVE 보존, 같은 RUN으로 재시도"
  if ! unit_stopped; then
    systemctl disable --now "$UNIT" > /dev/null 2>&1 ||
      die "유닛 중지·해제 실패 — ip_forward=0, 유닛·허용표 파일·ACTIVE 보존, 같은 RUN으로 재시도"
    unit_state || die "유닛 상태 재조회 실패 — ip_forward=0, 유닛·허용표 파일·ACTIVE 보존, 같은 RUN으로 재시도"
    unit_stopped || die "유닛이 아직 $UNIT_ACT/$UNIT_EN — ip_forward=0, 유닛·허용표 파일·ACTIVE 보존, 같은 RUN으로 재시도"
  fi
  echo "유닛: $UNIT_ACT/$UNIT_EN 확인"
  # 허용표: 조회 오류·삭제 실패·부재 확인 실패면 유닛·허용표 파일과 ACTIVE를 보존하고 멈춘다(같은 RUN 재시도).
  nft_table_state
  case $? in
    0) nft delete table inet fds_p2_vpn ||
         die "허용표 삭제 실패 — ip_forward=0·통제 파일·ACTIVE 보존, 같은 RUN으로 재시도" ;;
    1) : ;;
    *) die "nft 목록 조회 실패 — ip_forward=0·통제 파일·ACTIVE 보존, 같은 RUN으로 재시도" ;;
  esac
  nft_table_state
  [ $? = 1 ] || die "허용표 부재 확인 실패 — ip_forward=0·통제 파일·ACTIVE 보존, 같은 RUN으로 재시도"
  echo "허용표: 부재 확인"
  if [ -e "$UNIT_FILE" ]; then rm -f "$UNIT_FILE" || fail "$UNIT_FILE 삭제 실패"; fi
  if [ -e "$NFT_FILE" ]; then rm -f "$NFT_FILE" || fail "$NFT_FILE 삭제 실패"; fi
  [ -d "$NFT_DIR" ] && { rmdir "$NFT_DIR" 2>/dev/null || true; }
  systemctl daemon-reload || fail "daemon-reload 실패"

  # 4) sysctl 파일·런타임 값 복원(readback)
  if [ "$ROLE" = vpn-gw01 ]; then
    b=$dir/backup/$(basename "$GW_SYSCTL")
    if [ -e "$b" ]; then
      cp -a "$b" "$GW_SYSCTL" && cmp -s "$b" "$GW_SYSCTL" || fail "$GW_SYSCTL 복원 실패"
    else
      fail "$GW_SYSCTL 백업 없음 — 파일 복원 불가"
    fi
  fi
  # 런타임 ip_forward는 모든 정리·확인이 끝난 뒤(아래)에만 apply 전 값으로 되돌린다. 그 전까지 0 유지.

  # 5) 이 RUN에서 추가한 firewalld 항목만 제거
  #    있음·없음·조회 오류를 구분하고, 제거 뒤 부재를 다시 확인한다. 오류는 실패로 남겨 ip_forward=0·ACTIVE를 유지한다.
  if [ "$ROLE" = relay ]; then
    for p in 500 4500; do
      eval "b=\${port_$p:-no}"
      [ "$b" = no ] || continue
      fw_has --query-port "$p/udp"
      case $? in
        0) if firewall-cmd --permanent --zone "$zone" --remove-port "$p/udp" > /dev/null; then
             fw_has --query-port "$p/udp"
             [ $? = 1 ] || fail "port $p/udp 제거 뒤 부재 확인 실패"
           else
             fail "port $p/udp 제거 실패"
           fi ;;
        1) : ;;
        *) fail "port $p/udp 조회 실패" ;;
      esac
    done
  fi
  if [ "${zone_forward:-yes}" = no ]; then
    fw_has --query-forward
    case $? in
      0) if firewall-cmd --permanent --zone "$zone" --remove-forward > /dev/null; then
           fw_has --query-forward
           [ $? = 1 ] || fail "zone forward 제거 뒤 부재 확인 실패"
         else
           fail "zone forward 제거 실패"
         fi ;;
      1) : ;;
      *) fail "zone forward 조회 실패" ;;
    esac
  fi
  if [ "${firewalld_changed:-no}" = yes ]; then firewall-cmd --reload > /dev/null || fail "firewalld reload 실패"; fi

  # 6) ipsec.service를 apply 전 상태로(이 RUN이 켠 경우만 끈다)
  if [ "${ipsec_active:-active}" != active ] && systemctl is-active --quiet ipsec; then
    systemctl stop ipsec || fail "ipsec.service 중지 실패"
  fi
  if [ "${ipsec_enabled:-enabled}" != enabled ] && [ "$(systemctl is-enabled ipsec 2>/dev/null)" = enabled ]; then
    systemctl disable ipsec > /dev/null 2>&1 || fail "ipsec.service disable 실패"
  fi
  # apply 전부터 ipsec이 떠 있던 호스트는 계속 떠 있으므로, 지운 secrets를 pluto에서도 비운다(PR6 리뷰 C2).
  ipsec_svc_state
  case $? in
    0) if ipsec_cmd rereadsecrets; then echo "rereadsecrets rc=0"; else fail "rereadsecrets 실패 — pluto에 PSK가 남아 있을 수 있음"; fi ;;
    1) : ;;
    *) fail "ipsec 상태 확인 불가($IPSEC_SVC) — pluto 키 정리 미확인" ;;
  esac

  # 7) 정리가 모두 성공했을 때만 apply 전 런타임 ip_forward 복원(readback). 실패가 있으면 0 유지.
  if [ "${#failed[@]}" -eq 0 ]; then
    if sysctl -w "net.ipv4.ip_forward=${ip_forward_runtime:-0}" > /dev/null; then
      [ "$(sysctl -n net.ipv4.ip_forward)" = "${ip_forward_runtime:-0}" ] || fail "ip_forward 원복 readback 불일치"
    else
      fail "ip_forward=${ip_forward_runtime:-0} 원복 실패"
    fi
  fi
  if [ "${#failed[@]}" -gt 0 ]; then
    forward_off || failed+=("ip_forward=0 재확인 실패")
    echo "ROLLBACK_INCOMPLETE role=$ROLE run=$run failed=${#failed[@]} ip_forward=$(sysctl -n net.ipv4.ip_forward) — 원인 해소 뒤 같은 RUN으로 다시 rollback" >&2
    printf '  - %s\n' "${failed[@]}" >&2
    exit 1
  fi
  rm -f "$ACTIVE" || die "활성 RUN 표식 삭제 실패"
  # 이 RUN이 소유한 secrets를 지웠으므로 소유를 해제한다(실패하면 OWNER가 남아 새 RUN psk가 멈춘다).
  if [ "$(psk_owner)" = "$run" ]; then
    release_owner "$run" rollback || echo "WARN: psk 소유 해제 실패 — 새 RUN 전 수동 확인" >&2
  fi
  echo "ROLLBACK_DONE role=$ROLE run=$run"
  do_check
}

case "$CMD" in
  check) do_check ;;
  render) render "${3:?outdir}" ;;
  psk) do_psk "${3:-}" ;;
  psk-clean) do_psk_clean "${3:-}" ;;
  apply) do_apply "${3:-}" ;;
  up) [ "$ROLE" = vpn-gw01 ] || die "up은 개시자(vpn-gw01)만"; need_root; ipsec_cmd up "$CONN" ;;
  status) do_status ;;
  probe) do_probe "${3:-}" "${4:-}" "${5:-5}" ;;
  rollback) do_rollback "${3:-}" ;;
  *) die "명령: check|render|psk|psk-clean|apply|up|status|probe|rollback" ;;
esac
