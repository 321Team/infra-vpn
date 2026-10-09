#!/usr/bin/env bash
# P2-VPN-01 (#37) — vpn-gw01 ↔ AWS Relay IPsec(IKEv2, PSK) 구성·점검·원복.
#
#   sudo bash p2vpn.sh <relay|vpn-gw01> check                 읽기 전용 상태
#   bash      p2vpn.sh <relay|vpn-gw01> render <outdir>        설정 파일만 만든다(서버 변경 없음, CI·리뷰용)
#   sudo bash p2vpn.sh <relay|vpn-gw01> psk                   PSK를 화면 표시 없이 입력해 secrets 파일(0600)에 저장
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

do_psk() {
  need_root; identity_check
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
  umask 077
  tmp=$(mktemp "$IPSEC_D/.$CONN.secrets.XXXXXX") || { unset a; die "임시 파일 생성 실패"; }
  # 쓰기·권한·교체 중 하나라도 실패하면 임시 파일을 지우고 기존 secrets는 그대로 둔다.
  if ! printf '@fds-vpn-gw01 @fds-aws-relay01 : PSK "%s"\n' "$a" > "$tmp"; then
    unset a; rm -f "$tmp"; die "secrets 임시 파일 쓰기 실패 — 기존 secrets 유지"
  fi
  unset a
  if ! { chown root:root "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$SECRETS"; }; then
    rm -f "$tmp"; die "secrets 저장 실패 — 기존 secrets 유지"
  fi
  if command -v restorecon > /dev/null 2>&1; then restorecon "$SECRETS" || die "secrets SELinux 라벨 복원 실패"; fi
  secrets_report
  if systemctl is-active --quiet ipsec; then ipsec_cmd rereadsecrets && echo "rereadsecrets rc=0"; fi
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
  nft list table inet fds_p2_vpn > /dev/null 2>&1 && die "기존 fds_p2_vpn table 존재 — 소유 RUN 확인 필요"
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
  {
    echo "zone=$zone"
    echo "ip_forward_runtime=$fwd"
    echo "zone_forward=$(firewall-cmd --permanent --zone "$zone" --query-forward > /dev/null && echo yes || echo no)"
    for p in 500/udp 4500/udp; do
      echo "port_${p%/udp}=$(firewall-cmd --permanent --zone "$zone" --query-port "$p" > /dev/null && echo yes || echo no)"
    done
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
      if ! firewall-cmd --permanent --zone "$zone" --query-port "$p" > /dev/null; then
        firewall-cmd --permanent --zone "$zone" --add-port "$p" > /dev/null || apply_fail "port $p 추가 실패"
        changed=yes
      fi
    done
  fi
  if ! firewall-cmd --permanent --zone "$zone" --query-forward > /dev/null; then
    firewall-cmd --permanent --zone "$zone" --add-forward > /dev/null || apply_fail "zone forward 허용 실패"
    changed=yes
  fi
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

conn_loaded() { ipsec status 2>/dev/null | grep -qF "\"$CONN\""; }

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

  # 2) conn: 등록돼 있을 때만 지우고, 지운 뒤 남아 있으면 실패. 이미 없음과 실패를 구분한다.
  if systemctl is-active --quiet ipsec && conn_loaded; then
    ipsec_cmd delete "$CONN" || fail "conn 삭제 명령 실패"
    conn_loaded && fail "conn이 아직 등록돼 있음"
  else
    echo "conn: 등록 없음"
  fi
  if [ -e "$CONF" ]; then rm -f "$CONF" || fail "$CONF 삭제 실패"; fi
  if [ -e "$SECRETS" ]; then shred -u "$SECRETS" 2>/dev/null || rm -f "$SECRETS" || fail "secrets 삭제 실패"; fi
  [ -e "$SECRETS" ] && fail "secrets가 남아 있음"

  # 3) 유닛·허용표
  if [ -e "$UNIT_FILE" ]; then
    systemctl disable --now "$UNIT" > /dev/null 2>&1 || fail "유닛 중지·해제 실패"
    rm -f "$UNIT_FILE" || fail "$UNIT_FILE 삭제 실패"
  fi
  if [ -e "$NFT_FILE" ]; then rm -f "$NFT_FILE" || fail "$NFT_FILE 삭제 실패"; fi
  [ -d "$NFT_DIR" ] && { rmdir "$NFT_DIR" 2>/dev/null || true; }
  systemctl daemon-reload || fail "daemon-reload 실패"
  if nft list table inet fds_p2_vpn > /dev/null 2>&1; then
    nft delete table inet fds_p2_vpn || fail "허용표 삭제 실패"
    nft list table inet fds_p2_vpn > /dev/null 2>&1 && fail "허용표가 남아 있음"
  fi

  # 4) sysctl 파일·런타임 값 복원(readback)
  if [ "$ROLE" = vpn-gw01 ]; then
    b=$dir/backup/$(basename "$GW_SYSCTL")
    if [ -e "$b" ]; then
      cp -a "$b" "$GW_SYSCTL" && cmp -s "$b" "$GW_SYSCTL" || fail "$GW_SYSCTL 복원 실패"
    else
      fail "$GW_SYSCTL 백업 없음 — 파일 복원 불가"
    fi
  fi
  if sysctl -w "net.ipv4.ip_forward=${ip_forward_runtime:-0}" > /dev/null; then
    [ "$(sysctl -n net.ipv4.ip_forward)" = "${ip_forward_runtime:-0}" ] || fail "ip_forward 원복 readback 불일치"
  else
    fail "ip_forward=${ip_forward_runtime:-0} 원복 실패"
  fi

  # 5) 이 RUN에서 추가한 firewalld 항목만 제거
  if [ "$ROLE" = relay ]; then
    for p in 500 4500; do
      eval "b=\${port_$p:-no}"
      if [ "$b" = no ] && firewall-cmd --permanent --zone "$zone" --query-port "$p/udp" > /dev/null; then
        firewall-cmd --permanent --zone "$zone" --remove-port "$p/udp" > /dev/null || fail "port $p/udp 제거 실패"
      fi
    done
  fi
  if [ "${zone_forward:-yes}" = no ] && firewall-cmd --permanent --zone "$zone" --query-forward > /dev/null; then
    firewall-cmd --permanent --zone "$zone" --remove-forward > /dev/null || fail "zone forward 제거 실패"
  fi
  if [ "${firewalld_changed:-no}" = yes ]; then firewall-cmd --reload > /dev/null || fail "firewalld reload 실패"; fi

  # 6) ipsec.service를 apply 전 상태로(이 RUN이 켠 경우만 끈다)
  if [ "${ipsec_active:-active}" != active ] && systemctl is-active --quiet ipsec; then
    systemctl stop ipsec || fail "ipsec.service 중지 실패"
  fi
  if [ "${ipsec_enabled:-enabled}" != enabled ] && [ "$(systemctl is-enabled ipsec 2>/dev/null)" = enabled ]; then
    systemctl disable ipsec > /dev/null 2>&1 || fail "ipsec.service disable 실패"
  fi

  if [ "${#failed[@]}" -gt 0 ]; then
    echo "ROLLBACK_INCOMPLETE role=$ROLE run=$run failed=${#failed[@]} — 원인 해소 뒤 같은 RUN으로 다시 rollback" >&2
    printf '  - %s\n' "${failed[@]}" >&2
    exit 1
  fi
  rm -f "$ACTIVE" || die "활성 RUN 표식 삭제 실패"
  echo "ROLLBACK_DONE role=$ROLE run=$run"
  do_check
}

case "$CMD" in
  check) do_check ;;
  render) render "${3:?outdir}" ;;
  psk) do_psk ;;
  apply) do_apply "${3:-}" ;;
  up) [ "$ROLE" = vpn-gw01 ] || die "up은 개시자(vpn-gw01)만"; need_root; ipsec_cmd up "$CONN" ;;
  status) do_status ;;
  probe) do_probe "${3:-}" "${4:-}" "${5:-5}" ;;
  rollback) do_rollback "${3:-}" ;;
  *) die "명령: check|render|psk|apply|up|status|probe|rollback" ;;
esac
