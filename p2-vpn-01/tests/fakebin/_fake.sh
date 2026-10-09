#!/usr/bin/env bash
# 시험용 가짜 시스템 명령. 실제 서버를 바꾸지 않고 상태를 $FAKE_STATE 아래 파일로 흉내 낸다.
# 호출은 모두 $FAKE_STATE/calls.log 에 남긴다. 링크 이름(argv[0])으로 어떤 명령인지 정한다.
set -u
S=${FAKE_STATE:?}
name=$(basename "$0")
printf '%s %s\n' "$name" "$*" >> "$S/calls.log"
# 실패 주입: FAKE_FAIL(glob)이 "명령 인자" 전체와 맞으면 아무것도 바꾸지 않고 rc1.
if [ -n "${FAKE_FAIL:-}" ]; then
  # shellcheck disable=SC2053
  [[ "$name $*" == $FAKE_FAIL ]] && { echo "fake: injected failure: $name $*" >&2; exit 1; }
fi
get() { cat "$S/$1" 2>/dev/null || echo "${2:-}"; }
put() { printf '%s\n' "$2" > "$S/$1"; }

case "$name" in
  id) [ "${1:-}" = -u ] && { echo 0; exit 0; }; exec /usr/bin/id "$@" ;;
  chown) exit 0 ;;
  cp) exec /bin/cp "$@" ;;
  ip)
    case "$*" in
      "-4 -o addr show") printf '2: eth0    inet %s/24 brd x scope global eth0\n' "${FAKE_IP:?}" ;;
      "xfrm policy") printf 'src 10.20.0.0/16 dst 10.1.93.0/24\n\tdir out priority 1 ptype main\n\ttmpl src 10.20.110.10 dst 203.0.113.10\n' ;;
      "xfrm state") printf 'src 10.20.110.10 dst 203.0.113.10\n\tproto esp spi 0xc0ffee01 reqid 1 mode tunnel\n\treplay-window 32 flag af-unspec\n\tauth-trunc hmac(sha256) 0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 128\n\tenc cbc(aes) 0xfeedfacecafebeef0011223344556677feedfacecafebeef0011223344556677\n\tencap type espinudp sport 4500 dport 4500 addr 0.0.0.0\n' ;;
      *) exit 0 ;;
    esac ;;
  sysctl)
    case "$*" in
      "-n net.ipv4.ip_forward") get ip_forward 0 ;;
      "-w net.ipv4.ip_forward="*) put ip_forward "${2#net.ipv4.ip_forward=}"; echo "$2" ;;
      *) echo "net.ipv4.ip_forward = $(get ip_forward 0)"; echo "net.ipv4.conf.all.rp_filter = 0" ;;
    esac ;;
  firewall-cmd)
    perm=no; zone=public; action=""; arg=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --permanent) perm=yes ;;
        --zone) zone=$2; shift ;;
        --get-default-zone|--reload|--list-ports|--query-forward|--add-forward|--remove-forward) action=$1 ;;
        --query-port|--add-port|--remove-port) action=$1; arg=$2; shift ;;
      esac
      shift
    done
    [ "${FAKE_FIREWALLD_FAIL:-}" = "$action" ] && exit 1
    ports=$S/fw_ports; touch "$ports"
    case "$action" in
      --get-default-zone) echo public ;;
      --reload) echo success ;;
      --list-ports) tr '\n' ' ' < "$ports"; echo ;;
      --query-forward) [ "$(get fw_forward no)" = yes ] && { echo yes; exit 0; } || { echo no; exit 1; } ;;
      --add-forward) put fw_forward yes ;;
      --remove-forward) put fw_forward no ;;
      --query-port) grep -qx "$arg" "$ports" && { echo yes; exit 0; } || { echo no; exit 1; } ;;
      --add-port) grep -qx "$arg" "$ports" || echo "$arg" >> "$ports" ;;
      --remove-port) grep -vx "$arg" "$ports" > "$ports.tmp"; mv "$ports.tmp" "$ports" ;;
    esac ;;
  nft)
    case "$*" in
      "-c -f "*) [ "${FAKE_NFT_CHECK_FAIL:-}" = 1 ] && exit 1; grep -q 'table inet fds_p2_vpn {' "$3" ;;
      "-f "*) [ -f "$2" ] || exit 1; put nft_table present ;;
      "list table inet fds_p2_vpn") [ "$(get nft_table absent)" = present ] && echo "table inet fds_p2_vpn { counter packets 3 }" || exit 1 ;;
      "delete table inet fds_p2_vpn") [ "$(get nft_table absent)" = present ] || exit 1; put nft_table absent ;;
      *) exit 0 ;;
    esac ;;
  systemctl)
    unit=fds-p2-vpn-forward.service
    case "$*" in
      daemon-reload) exit 0 ;;
      "enable $unit") put unit_enabled yes ;;
      "restart $unit")
        [ "${FAKE_UNIT_FAIL:-}" = 1 ] && exit 1
        [ -f "${FAKE_NFT_FILE:?}" ] || exit 1
        put nft_table present; put unit_active active; put ip_forward 1 ;;
      "disable --now $unit") put unit_enabled no; put unit_active inactive; put ip_forward 0; put nft_table absent ;;
      "is-active $unit") get unit_active inactive ;;
      "is-enabled $unit") get unit_enabled disabled ;;
      "enable --now ipsec") put ipsec active; put ipsec_enabled enabled ;;
      "stop ipsec") put ipsec inactive ;;
      "disable ipsec") put ipsec_enabled disabled ;;
      "is-active --quiet ipsec") [ "$(get ipsec inactive)" = active ] ;;
      "is-active ipsec") get ipsec inactive; [ "$(get ipsec inactive)" = active ] ;;
      "is-enabled ipsec") get ipsec_enabled disabled; [ "$(get ipsec_enabled disabled)" = enabled ] ;;
      *) exit 0 ;;
    esac ;;
  ipsec)
    case "$*" in
      --version) echo "Libreswan ${FAKE_LS_VERSION:-5.4}" ;;
      "addconn --checkconfig --config "*) [ "${FAKE_CHECKCONFIG_FAIL:-}" = 1 ] && exit 1; grep -q '^conn fds-p2-vpn' "$4" ;;
      trafficstatus) [ -f "$S/conn_added" ] && echo '#1: "fds-p2-vpn", type=ESP, add_time=1, inBytes=10, outBytes=10' ;;
      status) [ -f "$S/conn_added" ] && echo '000 "fds-p2-vpn": 10.1.93.0/24===10.1.93.51...203.0.113.10===10.20.0.0/16; unrouted'; exit 0 ;;
      showstates) echo '#1: "fds-p2-vpn":4500 STATE_V2_ESTABLISHED_CHILD_SA SPI 0xdeadbeefdeadbeefdeadbeefdeadbeef' ;;
      "add fds-p2-vpn"|"auto --add fds-p2-vpn") touch "$S/conn_added" ;;
      "delete fds-p2-vpn"|"auto --delete fds-p2-vpn") rm -f "$S/conn_added" ;;
      *) exit 0 ;;
    esac ;;
  *) echo "fake: unknown $name" >&2; exit 99 ;;
esac
