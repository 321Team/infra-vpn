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
  printf '@fds-vpn-gw01 @fds-aws-relay01 : PSK "%s"\n' "$a" > "$tmp"
  unset a
  chown root:root "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$SECRETS" || die "secrets 저장 실패"
  command -v restorecon > /dev/null 2>&1 && restorecon "$SECRETS"
  secrets_report
  if systemctl is-active --quiet ipsec; then ipsec_cmd rereadsecrets && echo "rereadsecrets rc=0"; fi
}

do_apply() {
  need_root; identity_check
  local run=${1:-}; [[ "$run" =~ ^[0-9]{8}T[0-9]{4}$ ]] || die "RUN 형식 YYYYMMDDTHHMM 필요"
  local dir=$STATE_ROOT/$run; [ -e "$dir" ] && die "$dir 이미 있음 — 새 RUN 사용"
  [ -s "$SECRETS" ] || die "secrets 없음 — 먼저 psk"
  mkdir -p "$dir/backup" "$dir/staged" && chmod 700 "$STATE_ROOT" "$dir"
  render "$dir/staged" || die "render 실패"
  ipsec addconn --checkconfig --config "$dir/staged/ipsec-check.conf" || die "conn 문법 검사 실패"
  nft -c -f "$dir/staged/forward.nft" || die "nft 문법 검사 실패"

  say "backup"
  for f in "$CONF" "$NFT_FILE" "$UNIT_FILE" "$GW_SYSCTL" "$RELAY_SYSCTL"; do
    [ -e "$f" ] && cp -a "$f" "$dir/backup/" && echo "backup $f"
  done
  local zone; zone=$(firewall-cmd --get-default-zone) || die "firewalld 조회 실패"
  {
    echo "zone=$zone"
    echo "ip_forward_runtime=$(sysctl -n net.ipv4.ip_forward)"
    echo "zone_forward=$(firewall-cmd --permanent --zone "$zone" --query-forward > /dev/null && echo yes || echo no)"
    for p in 500/udp 4500/udp; do
      echo "port_${p%/udp}=$(firewall-cmd --permanent --zone "$zone" --query-port "$p" > /dev/null && echo yes || echo no)"
    done
  } > "$dir/state.env"
  cat "$dir/state.env"

  say "persistent ip_forward=0 (fail-closed; 유닛이 허용표 적재 뒤에만 켠다)"
  if [ "$ROLE" = vpn-gw01 ]; then
    [ -e "$GW_SYSCTL" ] || die "$GW_SYSCTL 없음"
    sed -i -E 's/^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=.*/net.ipv4.ip_forward = 0/' "$GW_SYSCTL"
    grep -q '^net.ipv4.ip_forward = 0$' "$GW_SYSCTL" || die "$GW_SYSCTL ip_forward=0 반영 실패"
  else
    grep -Eq '^net\.ipv4\.ip_forward *= *0$' "$RELAY_SYSCTL" || die "$RELAY_SYSCTL 이 ip_forward=0 이 아님"
  fi

  say "firewalld (permanent만 바꾸고, 바꾼 것이 있을 때만 reload)"
  local changed=no
  if [ "$ROLE" = relay ]; then
    for p in 500/udp 4500/udp; do
      if ! firewall-cmd --permanent --zone "$zone" --query-port "$p" > /dev/null; then
        firewall-cmd --permanent --zone "$zone" --add-port "$p" > /dev/null || die "port $p 추가 실패"
        changed=yes
      fi
    done
  fi
  if ! firewall-cmd --permanent --zone "$zone" --query-forward > /dev/null; then
    firewall-cmd --permanent --zone "$zone" --add-forward > /dev/null || die "zone forward 허용 실패"
    changed=yes
  fi
  if [ "$changed" = yes ]; then firewall-cmd --reload > /dev/null || die "firewalld reload 실패"; fi
  echo "firewalld_changed=$changed" | tee -a "$dir/state.env"

  say "install"
  install -d -m 0755 "$NFT_DIR"
  install -m 0644 "$dir/staged/forward.nft" "$NFT_FILE"
  install -m 0644 "$dir/staged/$CONN.conf" "$CONF"
  install -m 0644 "$dir/staged/$UNIT" "$UNIT_FILE"
  command -v restorecon > /dev/null 2>&1 && restorecon "$NFT_FILE" "$CONF" "$UNIT_FILE"
  systemctl daemon-reload
  systemctl enable "$UNIT" > /dev/null 2>&1 || die "유닛 enable 실패"
  systemctl restart "$UNIT" || die "유닛 시작 실패 — 포워딩은 꺼진 채로 둔다"
  nft list table inet fds_p2_vpn > /dev/null || die "허용표 없음"
  [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || die "ip_forward가 켜지지 않음"

  say "ipsec"
  systemctl enable --now ipsec > /dev/null 2>&1 || die "ipsec.service 시작 실패"
  ipsec_cmd rereadsecrets || die "rereadsecrets 실패"
  ipsec_cmd add "$CONN" || die "conn 등록 실패"
  sha256sum "$CONF" "$NFT_FILE" "$UNIT_FILE" | tee "$dir/installed.sha256"
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

do_rollback() {
  need_root; identity_check
  local run=${1:-}; local dir=$STATE_ROOT/$run
  [ -n "$run" ] && [ -f "$dir/state.env" ] || die "$dir/state.env 없음"
  # shellcheck disable=SC1091
  . "$dir/state.env"
  if systemctl is-active --quiet ipsec; then ipsec_cmd delete "$CONN" || echo "conn 삭제: 없음 또는 실패(계속)"; fi
  rm -f "$CONF"
  if [ -e "$SECRETS" ]; then shred -u "$SECRETS" 2>/dev/null || rm -f "$SECRETS"; fi
  systemctl disable --now "$UNIT" > /dev/null 2>&1 || true
  rm -f "$UNIT_FILE" "$NFT_FILE"; rmdir "$NFT_DIR" 2>/dev/null || true
  systemctl daemon-reload
  nft list table inet fds_p2_vpn > /dev/null 2>&1 && nft delete table inet fds_p2_vpn
  if [ "$ROLE" = vpn-gw01 ] && [ -e "$dir/backup/$(basename "$GW_SYSCTL")" ]; then
    cp -a "$dir/backup/$(basename "$GW_SYSCTL")" "$GW_SYSCTL"
  fi
  sysctl -w "net.ipv4.ip_forward=${ip_forward_runtime:-0}" > /dev/null
  if [ "$ROLE" = relay ]; then
    [ "${port_500:-no}" = no ] && firewall-cmd --permanent --zone "$zone" --remove-port 500/udp > /dev/null
    [ "${port_4500:-no}" = no ] && firewall-cmd --permanent --zone "$zone" --remove-port 4500/udp > /dev/null
  fi
  [ "${zone_forward:-yes}" = no ] && firewall-cmd --permanent --zone "$zone" --remove-forward > /dev/null
  if [ "${firewalld_changed:-no}" = yes ]; then firewall-cmd --reload > /dev/null || die "firewalld reload 실패"; fi
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
