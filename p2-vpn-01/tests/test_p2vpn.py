"""P2-VPN-01 (#37) 구성 패키지 시험.

- 정적: 양쪽 conn이 서로 거울인지, 비밀이 없는지, FORWARD 허용표·fail-closed 유닛 계약.
- render: 실제 스크립트로 파일을 만들고 입력 오류를 막는지(bash 필요).
- 컨테이너(P2VPN_CONTAINER_IT=1 + docker): CentOS Stream 9·10에 배포판 Libreswan·nftables를 설치해
  그 버전으로 `ipsec addconn --checkconfig`와 `nft -c -f`를 실행한다. 서버·클러스터에 접속하지 않는다.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

PKG = Path(__file__).resolve().parents[1]
SCRIPT = PKG / "p2vpn.sh"
IMAGES = {
    # quay.io/centos/centos 고정 digest(2026-10-25 조회 태그 manifest list). Relay AMI는 Stream 9, vpn-gw01은 Stream 10.
    # 이전 고정값(2026-10-07 빌드 33346f5f…·e6644126…, 2026-10-14 태그 4fdfb367…·1e345af5…)은 quay.io에서 삭제돼(manifest unknown) 교체했다.
    "stream9": "quay.io/centos/centos@sha256:6f8045fc4f552544d8a401d61848bafc8d06ca7c11897c5b54a2c37fc419a20a",
    "stream10": "quay.io/centos/centos@sha256:6f8d618844ed5af4365bad24bea19fb0435fd5ec808201af9aeb19d7a28eb515",
}
TEST_EIP = "203.0.113.10"  # RFC 5737 문서용 주소


def conn_settings(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "conn ")) and "=" in line:
            key, value = line.split("=", 1)
            out[key] = value
    return out


def seconds(value):
    m = re.fullmatch(r"(\d+)([smhd]?)", value)
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


class StaticContractTests(unittest.TestCase):
    def setUp(self):
        self.gw = conn_settings((PKG / "conf/vpn-gw01.conf.tmpl").read_text(encoding="utf-8"))
        self.relay = conn_settings((PKG / "conf/relay.conf.tmpl").read_text(encoding="utf-8"))

    def test_conns_mirror_each_other(self):
        gw, relay = self.gw, self.relay
        self.assertEqual((gw["leftid"], gw["rightid"]), (relay["rightid"], relay["leftid"]))
        self.assertEqual((gw["leftsubnet"], gw["rightsubnet"]), (relay["rightsubnet"], relay["leftsubnet"]))
        self.assertEqual((gw["leftsubnet"], gw["rightsubnet"]), ("10.1.93.0/24", "10.20.0.0/16"), "승인 selector")
        for key in ("authby", "ike", "esp", "encapsulation", "dpddelay", "retransmit-timeout"):
            self.assertEqual(gw[key], relay[key], key)
        self.assertEqual(gw["authby"], "secret")

    def test_roles_initiator_and_responder(self):
        self.assertEqual(self.gw["auto"], "start")
        self.assertEqual(self.relay["auto"], "add", "Relay는 응답만")
        self.assertEqual(self.relay["right"], "%any", "교육장 공인 IP가 바뀌므로 주소로 고정하지 않음")
        self.assertEqual(self.gw["right"], "@@RELAY_EIP@@")
        self.assertEqual(self.gw["left"], "10.1.93.51")
        # vpn-gw01이 먼저 rekey하도록 수명이 더 짧아야 한다
        self.assertLess(seconds(self.gw["ikelifetime"]), seconds(self.relay["ikelifetime"]))
        self.assertLess(seconds(self.gw["salifetime"]), seconds(self.relay["salifetime"]))
        # 개시자 rekey 예정 = 수명 - margin×(1~1+fuzz). 응답자는 수명 - margin/2(Libreswan rekeyfuzz.c, NETWORK.md §3.1)로
        # 더 늦다. 여기서는 Relay에도 개시자 식을 쓴 보수적 경우까지 vpn-gw01의 가장 늦은 rekey가 앞서는지 본다.
        for life in ("salifetime", "ikelifetime"):
            fuzz = {side: int(conf["rekeyfuzz"].rstrip("%")) / 100 for side, conf in (("gw", self.gw), ("relay", self.relay))}
            gw_latest = seconds(self.gw[life]) - seconds(self.gw["rekeymargin"])
            relay_earliest = seconds(self.relay[life]) - seconds(self.relay["rekeymargin"]) * (1 + fuzz["relay"])
            self.assertLess(gw_latest, relay_earliest, life)

    def test_no_secret_material_in_package(self):
        for path in PKG.rglob("*"):
            if path.is_file() and path.suffix in (".tmpl", ".sh", ".service", ".md", ".yml", ".nft"):
                text = path.read_text(encoding="utf-8")
                self.assertNotRegex(text, r'PSK\s+"[^"%]', f"{path}: PSK 값")
                self.assertNotRegex(text, r"(?i)set -x|bash -x|xtrace on", f"{path}: xtrace")

    def test_mss_clamp_both_directions_before_verdicts(self):
        # 10/22 창 B: worker MSS 8961 -> harbor01 TLS 응답이 ESP-in-UDP 터널 앞에서 버려졌다(vpn-gw01 IpFragFails).
        clamp = ("tcp flags & (syn | rst) == syn tcp option maxseg size 1361-65535 counter "
                 "tcp option maxseg size set 1360")
        for role in ("relay", "vpn-gw01"):
            text = (PKG / f"nft/{role}.nft.tmpl").read_text(encoding="utf-8")
            rules = [l.strip() for l in text.splitlines() if clamp in l]
            self.assertEqual(len(rules), 2, f"{role}: 양방향 2줄")
            self.assertTrue(any("ip saddr 10.20.0.0/16" in r for r in rules), role)
            self.assertTrue(any("ip daddr 10.20.0.0/16" in r for r in rules), role)
            for r in rules:  # MSS만 바꾸고 허용·차단 판정은 하지 않는다
                self.assertNotRegex(r, r"(accept|drop|reject|jump|goto)", role)
            first_jump = text.index("jump ")
            self.assertTrue(all(text.index(r) < first_jump for r in rules), f"{role}: 판정 체인보다 먼저")

    def test_forward_tables_fail_closed(self):
        for role in ("relay", "vpn-gw01"):
            text = (PKG / f"nft/{role}.nft.tmpl").read_text(encoding="utf-8")
            self.assertIn("rt ipsec missing counter drop", text, role)
            self.assertIn("meta ipsec missing counter drop", text, role)
            self.assertIn("ip saddr 10.20.10.0/24 ip daddr 10.1.93.55 tcp dport 5432 ct state new", text, role)
            self.assertIn("@@HARBOR@@", text)
            self.assertNotRegex(text, r"(?i)\b(masquerade|snat|dnat)\b", "Relay·게이트웨이에서 NAT 금지")
        self.assertIn("policy drop;", (PKG / "nft/relay.nft.tmpl").read_text(encoding="utf-8"))
        unit = (PKG / "systemd/fds-p2-vpn-forward.service").read_text(encoding="utf-8")
        start = unit.index("ExecStart=/usr/sbin/nft -f")
        self.assertLess(start, unit.index("ExecStartPost=/usr/sbin/sysctl -w net.ipv4.ip_forward=1"))
        self.assertIn("ExecStop=/usr/sbin/sysctl -w net.ipv4.ip_forward=0", unit)
        # R1: 시작 전 0, 최초 시작 실패(ExecStop 없음)에도 ExecStopPost가 0을 확인한 뒤에만 허용표를 지운다
        self.assertLess(unit.index("ExecStartPre=/usr/sbin/sysctl -w net.ipv4.ip_forward=0"), start)
        post = next(line for line in unit.splitlines() if line.startswith("ExecStopPost="))
        self.assertFalse(post.startswith("ExecStopPost=-"), "실패를 무시하지 않는다")
        self.assertLess(post.index("ip_forward=0"), post.index("nft delete table"))
        self.assertIn('test "$$(/usr/sbin/sysctl -n net.ipv4.ip_forward)" = 0 || exit 1', post,
                      "systemd 변수 확장을 피하려고 $$ 사용, 0 확인 실패 시 허용표를 지우지 않음")
        # 6163219831 R1: 표 목록 조회 오류를 부재로 보지 않고, 삭제·부재 확인 실패도 nonzero
        self.assertNotIn("2>&1; then", post, "조회 오류를 숨기는 'list table … 2>&1' 분기 금지")
        self.assertEqual(post.count("tables=$$(/usr/sbin/nft list tables) || exit 1"), 2)
        self.assertIn("nft delete table inet fds_p2_vpn || exit 1", post)
        self.assertNotIn('"%s', post, "systemd 지정자 %s 확장을 피하려고 %%s 사용")
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("net.ipv4.ip_forward = 0", script, "영구 sysctl은 0, 유닛만 켠다")


@unittest.skipUnless(shutil.which("bash"), "bash 필요")
class RenderTests(unittest.TestCase):
    def render(self, role, **env):
        out = tempfile.mkdtemp(prefix=f"p2vpn-{role}-")
        self.addCleanup(shutil.rmtree, out, True)
        full = dict(os.environ, **env)
        done = subprocess.run(["bash", str(SCRIPT), role, "render", out], capture_output=True, text=True, env=full)
        return done, Path(out)

    def test_render_both_roles_and_versions(self):
        for role, major, keyword in (("relay", "4", "ikev2=insist"), ("vpn-gw01", "5", "keyexchange=ikev2"),
                                     ("relay", "5", "keyexchange=ikev2"), ("vpn-gw01", "4", "ikev2=insist")):
            done, out = self.render(role, LIBRESWAN_MAJOR=major, RELAY_EIP=TEST_EIP)
            self.assertEqual(done.returncode, 0, done.stderr)
            conf = (out / "fds-p2-vpn.conf").read_text(encoding="utf-8")
            self.assertIn(f"\t{keyword}\n", conf)
            self.assertNotIn("@@", conf + (out / "forward.nft").read_text(encoding="utf-8"))
            self.assertTrue((out / "ipsec-check.conf").read_text(encoding="utf-8").startswith("config setup"))
            nft = (out / "forward.nft").read_text(encoding="utf-8")
            self.assertNotIn("10.1.93.54", nft, "Harbor 규칙은 기본 꺼짐")
        done, out = self.render("vpn-gw01", LIBRESWAN_MAJOR="5", RELAY_EIP=TEST_EIP)
        self.assertIn(f"right={TEST_EIP}", (out / "fds-p2-vpn.conf").read_text(encoding="utf-8"))

    def test_render_rejects_bad_inputs(self):
        for env, msg in (({"LIBRESWAN_MAJOR": "5"}, "RELAY_EIP 필요"),
                         ({"LIBRESWAN_MAJOR": "5", "RELAY_EIP": "10.20.110.10"}, "사설 주소"),
                         ({"LIBRESWAN_MAJOR": "6", "RELAY_EIP": TEST_EIP}, "지원하지 않는")):
            done, _ = self.render("vpn-gw01", **env)
            self.assertNotEqual(done.returncode, 0, env)
            self.assertIn(msg, done.stderr)
        done = subprocess.run(["bash", str(SCRIPT), "aws", "check"], capture_output=True, text=True)
        self.assertNotEqual(done.returncode, 0)

    def test_harbor_rule_only_when_enabled(self):
        for role in ("relay", "vpn-gw01"):
            done, out = self.render(role, LIBRESWAN_MAJOR="5", RELAY_EIP=TEST_EIP, FDS_HARBOR="on")
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("ip saddr 10.20.10.0/24 ip daddr 10.1.93.54 tcp dport 443 ct state new",
                          (out / "forward.nft").read_text(encoding="utf-8"))


FAKE_TOOLS = ("id", "chown", "cp", "ip", "sysctl", "firewall-cmd", "nft", "systemctl", "ipsec")
PSK = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6"  # 시험용 값(64자)
PSK_RUN = "20261012T0900"


@unittest.skipUnless(shutil.which("bash") and os.name != "nt", "Linux bash 필요 — CI에서 실행")
class FakeHostTests(unittest.TestCase):
    """가짜 시스템 명령과 경로 접두사로 psk·apply·status·rollback 전체 흐름을 실행한다(서버 변경 없음)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="p2vpn-host-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.prefix, self.state, self.bin = self.root / "fs", self.root / "state", self.root / "bin"
        for d in (self.prefix / "etc/ipsec.d", self.prefix / "etc/sysctl.d", self.prefix / "etc/systemd/system",
                  self.prefix / "root", self.state, self.bin):
            d.mkdir(parents=True)
        src = (PKG / "tests/fakebin/_fake.sh").read_text(encoding="utf-8")
        for name in FAKE_TOOLS:
            (self.bin / name).write_text(src, encoding="utf-8")
            os.chmod(self.bin / name, 0o755)

    def host(self, role, ip_forward, fw_forward="no", ports=(), ipsec_active=False):
        (self.state / "ip_forward").write_text(f"{ip_forward}\n")
        if ipsec_active:
            (self.state / "ipsec").write_text("active\n")
        (self.state / "fw_forward").write_text(f"{fw_forward}\n")
        (self.state / "fw_ports").write_text("".join(f"{p}\n" for p in ports))
        if role == "relay":
            self.ip = "10.20.110.10"
            (self.prefix / "etc/sysctl.d/90-fds-relay-bootstrap.conf").write_text("net.ipv4.ip_forward = 0\n")
        else:
            self.ip = "10.1.93.51"
            (self.prefix / "etc/sysctl.d/99-fds-p2-vpn-gw.conf").write_text(
                "net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=0\n")

    def run_cmd(self, role, *args, stdin=None, **env):
        full = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}", P2VPN_PREFIX=str(self.prefix),
                    FAKE_STATE=str(self.state), FAKE_IP=self.ip,
                    FAKE_NFT_FILE=str(self.prefix / "etc/fds-p2-vpn/forward.nft"), RELAY_EIP=TEST_EIP, **env)
        return subprocess.run(["bash", str(SCRIPT), role, *args], input=stdin, capture_output=True, text=True,
                              env=full)

    def st(self, name):
        path = self.state / name
        return path.read_text().strip() if path.exists() else ""

    def calls(self):
        return (self.state / "calls.log").read_text().splitlines() if (self.state / "calls.log").exists() else []

    def psk(self, role, run=PSK_RUN):
        done = self.run_cmd(role, "psk", run, stdin=f"{PSK}\n{PSK}\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        return done

    def test_psk_writes_0600_without_echo(self):
        self.host("relay", 0)
        done = self.psk("relay")
        secrets = self.prefix / "etc/ipsec.d/fds-p2-vpn.secrets"
        self.assertEqual(secrets.read_text(), f'@fds-vpn-gw01 @fds-aws-relay01 : PSK "{PSK}"\n')
        self.assertEqual(oct(secrets.stat().st_mode & 0o777), "0o600")
        self.assertNotIn(PSK, done.stdout + done.stderr, "PSK가 출력에 나오면 안 된다")
        self.assertNotIn(PSK, "\n".join(self.calls()), "PSK가 명령 인자로 넘어가면 안 된다")
        self.assertIn("secrets: present", done.stdout)
        crlf = self.run_cmd("relay", "psk", PSK_RUN, stdin=f"{PSK}\r\n{PSK}\r\n")
        self.assertEqual(crlf.returncode, 0, crlf.stderr)
        self.assertEqual(secrets.read_bytes(), f'@fds-vpn-gw01 @fds-aws-relay01 : PSK "{PSK}"\n'.encode(),
                         "붙여넣기의 줄 끝 CR은 지운다")
        self.assertEqual(list((self.prefix / "etc/ipsec.d").glob(".fds-p2-vpn.secrets.*")), [], "임시 파일 남김 없음")
        for bad, msg in ((f"{PSK}\n{PSK}x\n", "두 입력이 다름"), ("short\nshort\n", "32자 이상"),
                         ('a"' + "b" * 40 + '\n' + 'a"' + "b" * 40 + "\n", "따옴표"),
                         ("a\x1b" + "b" * 40 + "\n" + "a\x1b" + "b" * 40 + "\n", "제어 문자")):
            failed = self.run_cmd("relay", "psk", PSK_RUN, stdin=bad)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn(msg, failed.stderr)
        self.assertEqual(secrets.read_text(), f'@fds-vpn-gw01 @fds-aws-relay01 : PSK "{PSK}"\n', "실패 시 기존 유지")

    def test_relay_apply_then_rollback_restores_everything(self):
        self.host("relay", 0, fw_forward="no")
        self.psk("relay", "20261012T1000")
        done = self.run_cmd("relay", "apply", "20261012T1000")
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)
        self.assertIn("APPLY_OK role=relay", done.stdout)
        installed = self.prefix / "etc/ipsec.d/fds-p2-vpn.conf"
        self.assertIn("rightid=@fds-vpn-gw01", installed.read_text())
        self.assertEqual((self.st("ip_forward"), self.st("nft_table"), self.st("unit_active")),
                         ("1", "present", "active"))
        self.assertEqual(sorted(self.st("fw_ports").split()), ["4500/udp", "500/udp"])
        self.assertEqual(self.st("fw_forward"), "yes")
        self.assertTrue((self.state / "conn_added").exists())
        calls = self.calls()
        self.assertEqual(sum(c == "firewall-cmd --reload" for c in calls), 1)
        nft_load = next(i for i, c in enumerate(calls) if c.startswith("systemctl restart fds-p2-vpn-forward"))
        checkconfig = next(i for i, c in enumerate(calls) if "addconn --checkconfig" in c)
        self.assertLess(checkconfig, nft_load, "문법 검사 뒤에 설치·적재")
        self.assertIn("ipsec add fds-p2-vpn", calls, "Libreswan 5.x 명령")
        self.assertEqual((self.prefix / "etc/sysctl.d/90-fds-relay-bootstrap.conf").read_text(),
                         "net.ipv4.ip_forward = 0\n", "영구 sysctl은 0 유지")
        state = (self.prefix / "root/fds-p2-vpn/20261012T1000/state.env").read_text()
        self.assertIn("zone_forward=no", state)
        self.assertIn("port_500=no", state)
        self.assertIn("firewalld_changed=yes", state)
        again = self.run_cmd("relay", "apply", "20261012T1000")
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("이미 있음", again.stderr)

        back = self.run_cmd("relay", "rollback", "20261012T1000")
        self.assertEqual(back.returncode, 0, back.stderr + back.stdout)
        self.assertIn("ROLLBACK_DONE", back.stdout)
        for rel in ("etc/ipsec.d/fds-p2-vpn.conf", "etc/ipsec.d/fds-p2-vpn.secrets", "etc/fds-p2-vpn/forward.nft",
                    "etc/systemd/system/fds-p2-vpn-forward.service"):
            self.assertFalse((self.prefix / rel).exists(), rel)
        self.assertEqual((self.st("ip_forward"), self.st("nft_table"), self.st("fw_forward")), ("0", "absent", "no"))
        self.assertEqual(self.st("fw_ports"), "")
        self.assertFalse((self.state / "conn_added").exists())
        self.assertEqual((self.st("ipsec"), self.st("ipsec_enabled")), ("inactive", "disabled"),
                         "apply 전 꺼져 있던 ipsec.service로 되돌림")
        self.assertFalse((self.prefix / "root/fds-p2-vpn/ACTIVE_RUN").exists())

    def test_vpn_gw01_apply_makes_persistent_forwarding_fail_closed_and_rollback_restores(self):
        self.host("vpn-gw01", 1, fw_forward="yes")
        self.psk("vpn-gw01", "20261012T1010")
        done = self.run_cmd("vpn-gw01", "apply", "20261012T1010", FAKE_LS_VERSION="5.4")
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)
        gw = self.prefix / "etc/sysctl.d/99-fds-p2-vpn-gw.conf"
        self.assertEqual(gw.read_text(), "net.ipv4.ip_forward = 0\nnet.ipv4.conf.all.rp_filter=0\n")
        self.assertEqual(self.st("ip_forward"), "1", "런타임은 유닛이 허용표 적재 뒤 켬")
        self.assertIn(f"right={TEST_EIP}", (self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").read_text())
        self.assertNotIn("firewall-cmd --reload", self.calls(), "바뀐 것이 없으면 reload하지 않는다")
        self.assertEqual(self.st("fw_ports"), "", "개시자는 IKE 포트를 열지 않는다")
        back = self.run_cmd("vpn-gw01", "rollback", "20261012T1010")
        self.assertEqual(back.returncode, 0, back.stderr + back.stdout)
        self.assertEqual(gw.read_text(), "net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=0\n", "원래 파일 복원")
        self.assertEqual((self.st("ip_forward"), self.st("fw_forward")), ("1", "yes"), "apply 전 상태")

    def test_libreswan4_uses_auto_commands(self):
        self.host("relay", 0, fw_forward="yes", ports=("500/udp", "4500/udp"))
        self.psk("relay", "20261012T1020")
        done = self.run_cmd("relay", "apply", "20261012T1020", FAKE_LS_VERSION="4.15")
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)
        self.assertIn("\tikev2=insist\n", (self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").read_text())
        self.assertIn("ipsec auto --add fds-p2-vpn", self.calls())
        self.assertNotIn("firewall-cmd --reload", self.calls())

    def test_apply_stops_before_changes_on_failures(self):
        cases = (({}, "secrets 없음", False), ({"FAKE_CHECKCONFIG_FAIL": "1"}, "conn 문법 검사 실패", True),
                 ({"FAKE_NFT_CHECK_FAIL": "1"}, "nft 문법 검사 실패", True))
        for i, (env, msg, with_psk) in enumerate(cases):
            self.setUp()
            self.host("relay", 0)
            if with_psk:
                self.psk("relay", f"20261012T110{i}")
            done = self.run_cmd("relay", "apply", f"20261012T110{i}", **env)
            self.assertNotEqual(done.returncode, 0, env)
            self.assertIn(msg, done.stderr)
            self.assertFalse((self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").exists(), "설치 전 중단")
            self.assertEqual((self.st("ip_forward"), self.st("fw_ports")), ("0", ""))

    def test_unit_failure_keeps_forwarding_off(self):
        self.host("relay", 0)
        self.psk("relay", "20261012T1200")
        done = self.run_cmd("relay", "apply", "20261012T1200", FAKE_UNIT_FAIL="1")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("포워딩은 꺼진 채로 둔다", done.stderr)
        self.assertEqual(self.st("ip_forward"), "0")
        self.assertFalse((self.state / "conn_added").exists(), "포워딩이 없으면 conn도 등록하지 않는다")

    def test_identity_guard_and_status_redaction(self):
        self.host("relay", 0)
        self.ip = "10.1.93.51"
        wrong = self.run_cmd("relay", "psk", PSK_RUN, stdin=f"{PSK}\n{PSK}\n")
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn("Relay가 아님", wrong.stderr)
        self.ip = "10.20.110.10"
        status = self.run_cmd("relay", "status")
        self.assertEqual(status.returncode, 0, status.stderr)
        for secret in ("00112233445566778899aabbccddeeff", "feedfacecafebeef", "deadbeefdeadbeef"):
            self.assertNotIn(secret, status.stdout, "xfrm 키·SPI 긴 값은 가린다")
        self.assertIn("<redacted>", status.stdout)
        self.assertNotIn("auth-trunc", status.stdout)

    # ---- 리뷰 R1~R4 회귀 ----
    GW_ORIG = "net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=0\n"

    def gw_file(self):
        return self.prefix / "etc/sysctl.d/99-fds-p2-vpn-gw.conf"

    def active(self):
        path = self.prefix / "root/fds-p2-vpn/ACTIVE_RUN"
        return path.read_text().strip() if path.exists() else ""

    def test_r1_unit_start_failure_with_forwarding_already_on(self):
        self.host("vpn-gw01", 1, fw_forward="yes")
        self.psk("vpn-gw01", "20261012T1300")
        done = self.run_cmd("vpn-gw01", "apply", "20261012T1300", FAKE_UNIT_FAIL="1")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("포워딩은 꺼진 채로 둔다", done.stderr)
        self.assertIn("ip_forward=0 확인", done.stderr)
        self.assertNotIn("APPLY_OK", done.stdout)
        self.assertEqual(self.st("ip_forward"), "0", "기존 런타임 1이어도 허용표 없이 1로 남지 않는다")
        self.assertFalse((self.state / "conn_added").exists())
        self.assertEqual(self.active(), "20261012T1300", "실패한 RUN은 rollback 대상으로 남는다")
        back = self.run_cmd("vpn-gw01", "rollback", "20261012T1300")
        self.assertEqual(back.returncode, 0, back.stderr + back.stdout)
        self.assertEqual(self.gw_file().read_text(), self.GW_ORIG)
        self.assertEqual(self.st("ip_forward"), "1")

    def test_r2_backup_failure_stops_before_host_changes(self):
        self.host("vpn-gw01", 1, fw_forward="no")
        self.psk("vpn-gw01", "20261012T1310")
        done = self.run_cmd("vpn-gw01", "apply", "20261012T1310", FAKE_FAIL="cp -a *99-fds-p2-vpn-gw.conf*")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("백업 실패", done.stderr)
        self.assertNotIn("APPLY_OK", done.stdout)
        self.assertEqual(self.gw_file().read_text(), self.GW_ORIG, "원본 sysctl 유지")
        self.assertEqual((self.st("ip_forward"), self.st("fw_forward")), ("1", "no"), "런타임·firewalld 그대로")
        self.assertFalse((self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").exists())
        self.assertEqual(self.active(), "", "호스트 변경 전 중단이라 활성 RUN 없음")

    def test_r2_install_step_failure_has_no_success_marker_and_rolls_back(self):
        for i, pattern in enumerate(("systemctl daemon-reload", "systemctl enable fds-p2-vpn-forward.service",
                                     "ipsec add fds-p2-vpn")):
            if i:
                self.setUp()
            self.host("vpn-gw01", 1, fw_forward="yes")
            run = f"20261012T132{i}"
            self.psk("vpn-gw01", run)
            done = self.run_cmd("vpn-gw01", "apply", run, FAKE_FAIL=pattern)
            self.assertNotEqual(done.returncode, 0, pattern)
            self.assertNotIn("APPLY_OK", done.stdout, pattern)
            self.assertEqual(self.st("ip_forward"), "0", pattern)
            self.assertEqual(self.active(), run, pattern)
            back = self.run_cmd("vpn-gw01", "rollback", run)
            self.assertEqual(back.returncode, 0, pattern + back.stderr + back.stdout)
            self.assertEqual(self.gw_file().read_text(), self.GW_ORIG, pattern)
            # 유닛을 시작하기 전에 실패한 경우 허용표는 올라간 적이 없다(가짜 상태 파일 없음 = 없음)
            self.assertEqual(self.st("ip_forward"), "1", pattern)
            self.assertNotEqual(self.st("nft_table"), "present", pattern)
            self.assertNotIn(self.st("unit_active"), ("active",), pattern)
            self.assertEqual(self.active(), "", pattern)

    def test_r3_new_run_refused_while_previous_install_exists(self):
        self.host("vpn-gw01", 1, fw_forward="yes")
        self.psk("vpn-gw01", "20261012T1400")
        first = self.run_cmd("vpn-gw01", "apply", "20261012T1400")
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        conf = (self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").read_bytes()
        calls_before = len(self.calls())
        second = self.run_cmd("vpn-gw01", "apply", "20261012T1401")
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("활성 RUN 있음(20261012T1400)", second.stderr)
        self.assertFalse((self.prefix / "root/fds-p2-vpn/20261012T1401").exists(), "새 RUN은 상태 폴더도 만들지 않는다")
        self.assertEqual((self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").read_bytes(), conf)
        self.assertFalse(any(c.startswith(("systemctl restart", "firewall-cmd --permanent --zone public --add"))
                             for c in self.calls()[calls_before:]), "거부는 무변경")
        # 표식이 사라져도 설치 파일이 남아 있으면 덮어쓰지 않는다
        marker = self.prefix / "root/fds-p2-vpn/ACTIVE_RUN"
        marker.unlink()
        third = self.run_cmd("vpn-gw01", "apply", "20261012T1402")
        self.assertNotEqual(third.returncode, 0)
        self.assertIn("기존 설치 존재", third.stderr)
        marker.write_text("20261012T1400\n")
        back = self.run_cmd("vpn-gw01", "rollback", "20261012T1400")
        self.assertEqual(back.returncode, 0, back.stderr + back.stdout)
        self.assertEqual((self.st("ip_forward"), self.st("nft_table")), ("1", "absent"))
        self.assertFalse((self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").exists())
        self.assertEqual(self.gw_file().read_text(), self.GW_ORIG)

    def test_r3_rollback_of_other_run_refused(self):
        self.host("relay", 0)
        self.psk("relay", "20261012T1410")
        self.assertEqual(self.run_cmd("relay", "apply", "20261012T1410").returncode, 0)
        other_dir = self.prefix / "root/fds-p2-vpn/20261012T1409"
        other_dir.mkdir()
        (other_dir / "state.env").write_text("zone=public\n")
        other = self.run_cmd("relay", "rollback", "20261012T1409")
        self.assertNotEqual(other.returncode, 0)
        self.assertIn("활성 RUN은 20261012T1410", other.stderr)
        self.assertEqual(self.st("nft_table"), "present", "다른 RUN 원복 시도는 무변경")

    def test_r4_rollback_failure_is_reported_and_retryable(self):
        self.host("vpn-gw01", 1, fw_forward="yes")
        self.psk("vpn-gw01", "20261012T1500")
        self.assertEqual(self.run_cmd("vpn-gw01", "apply", "20261012T1500").returncode, 0)
        bad = self.run_cmd("vpn-gw01", "rollback", "20261012T1500", FAKE_FAIL="sysctl -w net.ipv4.ip_forward=1")
        self.assertNotEqual(bad.returncode, 0)
        self.assertNotIn("ROLLBACK_DONE", bad.stdout)
        self.assertIn("ROLLBACK_INCOMPLETE", bad.stderr)
        self.assertIn("ip_forward=1 원복 실패", bad.stderr)
        self.assertEqual(self.st("ip_forward"), "0")
        self.assertEqual(self.active(), "20261012T1500", "미완료면 활성 RUN 유지")
        again = self.run_cmd("vpn-gw01", "rollback", "20261012T1500")
        self.assertEqual(again.returncode, 0, again.stderr + again.stdout)
        self.assertIn("ROLLBACK_DONE", again.stdout)
        self.assertEqual(self.st("ip_forward"), "1")
        self.assertEqual(self.active(), "")

    def test_r4_forwarding_off_must_succeed_before_controls_are_removed(self):
        self.host("relay", 0)
        self.psk("relay", "20261012T1510")
        self.assertEqual(self.run_cmd("relay", "apply", "20261012T1510").returncode, 0)
        bad = self.run_cmd("relay", "rollback", "20261012T1510", FAKE_FAIL="sysctl -w net.ipv4.ip_forward=0")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("허용표를 그대로 두고 중단", bad.stderr)
        self.assertEqual(self.st("nft_table"), "present", "포워딩을 끄지 못하면 허용표를 지우지 않는다")
        self.assertTrue((self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").exists())
        self.assertNotIn("ROLLBACK_DONE", bad.stdout)
        fw = self.run_cmd("relay", "rollback", "20261012T1510",
                          FAKE_FAIL="firewall-cmd --permanent --zone public --remove-forward")
        self.assertNotEqual(fw.returncode, 0)
        self.assertIn("zone forward 제거 실패", fw.stderr)
        self.assertNotIn("ROLLBACK_DONE", fw.stdout)
        self.assertEqual(self.st("ip_forward"), "0", "정리 실패 시 0 유지")
        final = self.run_cmd("relay", "rollback", "20261012T1510")
        self.assertEqual(final.returncode, 0, final.stderr + final.stdout)
        self.assertEqual((self.st("ip_forward"), self.st("nft_table"), self.st("fw_forward")), ("0", "absent", "no"))
        self.assertEqual(self.st("fw_ports"), "")

    def test_r4b_cleanup_failures_keep_forwarding_off_and_controls(self):
        """조회·삭제·중지·방화벽 실패: rc!=0, 성공표식 없음, ACTIVE 유지, ip_forward=0. 같은 RUN 재시도 성공."""
        cases = (
            ("ipsec delete fds-p2-vpn", "conn 삭제 실패", True),
            ("ipsec status", "conn 조회 실패", True),
            ("systemctl is-active ipsec", "ipsec.service 상태 불확실", True),
            ("systemctl disable --now fds-p2-vpn-forward.service", "유닛 중지·해제 실패", False),
            ("systemctl is-active fds-p2-vpn-forward.service", "유닛 상태 조회 실패", False),
        )
        n = 0
        for role, orig in (("relay", 0), ("vpn-gw01", 1)):
            for pattern, msg, controls_kept in cases:
                n += 1
                self.setUp()
                self.host(role, orig, fw_forward="yes")
                run = f"20261012T16{n:02d}"
                self.psk(role, run)
                self.assertEqual(self.run_cmd(role, "apply", run).returncode, 0, (role, pattern))
                bad = self.run_cmd(role, "rollback", run, FAKE_FAIL=pattern)
                ctx = (role, pattern, bad.stdout, bad.stderr)
                self.assertNotEqual(bad.returncode, 0, ctx)
                self.assertNotIn("ROLLBACK_DONE", bad.stdout, ctx)
                self.assertIn(msg, bad.stderr, ctx)
                self.assertEqual(self.st("ip_forward"), "0", ctx)
                self.assertEqual(self.active(), run, ctx)
                if controls_kept:
                    self.assertEqual(self.st("nft_table"), "present", ctx)
                    self.assertTrue((self.state / "conn_added").exists(), ctx)
                    self.assertTrue((self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").exists(), ctx)
                # 유닛 단계 이전에 멈췄으면(모든 경우) 재시도에 필요한 유닛·허용표 파일이 남아 있어야 한다
                for rel in ("etc/systemd/system/fds-p2-vpn-forward.service", "etc/fds-p2-vpn/forward.nft"):
                    self.assertTrue((self.prefix / rel).exists(), (ctx, rel))
                again = self.run_cmd(role, "rollback", run)
                self.assertEqual(again.returncode, 0, (role, pattern, again.stderr, again.stdout))
                self.assertIn("ROLLBACK_DONE", again.stdout)
                self.assertEqual((self.st("ip_forward"), self.st("nft_table")), (str(orig), "absent"), (role, pattern))
                self.assertEqual((self.st("unit_active"), self.st("unit_enabled")), ("inactive", "disabled"),
                                 (role, pattern))
                self.assertFalse((self.state / "conn_added").exists(), (role, pattern))
                self.assertEqual(self.active(), "", (role, pattern))

    def test_r4b_conn_absent_and_ipsec_inactive_are_not_failures(self):
        self.host("relay", 0)
        self.psk("relay", "20261012T1700")
        self.assertEqual(self.run_cmd("relay", "apply", "20261012T1700").returncode, 0)
        (self.state / "conn_added").unlink()  # 조회 성공·등록 없음
        done = self.run_cmd("relay", "rollback", "20261012T1700")
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)
        self.assertIn("conn: 등록 없음(조회 확인)", done.stdout)
        self.setUp()
        self.host("relay", 0)
        self.psk("relay", "20261012T1701")
        self.assertEqual(self.run_cmd("relay", "apply", "20261012T1701").returncode, 0)
        (self.state / "ipsec").write_text("inactive\n")  # ipsec.service가 내려가 있으면 conn 적재 없음
        done = self.run_cmd("relay", "rollback", "20261012T1701")
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)
        self.assertIn("ipsec.service: inactive", done.stdout)

    def test_r4c_unit_left_running_without_files_is_stopped_and_blocks_apply(self):
        """리뷰 5467915112 1: 파일이 없어도 active/enabled 유닛은 성공으로 보지 않는다."""
        self.host("vpn-gw01", 1, fw_forward="yes")
        self.psk("vpn-gw01", "20261012T1800")
        self.assertEqual(self.run_cmd("vpn-gw01", "apply", "20261012T1800").returncode, 0)
        for rel in ("etc/systemd/system/fds-p2-vpn-forward.service", "etc/fds-p2-vpn/forward.nft"):
            (self.prefix / rel).unlink()  # 파일만 사라지고 유닛은 active/enabled로 남은 상태
        self.assertEqual((self.st("unit_active"), self.st("unit_enabled")), ("active", "enabled"))
        done = self.run_cmd("vpn-gw01", "rollback", "20261012T1800")
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)
        self.assertIn("ROLLBACK_DONE", done.stdout)
        self.assertIn("systemctl disable --now fds-p2-vpn-forward.service", self.calls())
        self.assertEqual((self.st("unit_active"), self.st("unit_enabled"), self.st("ip_forward")),
                         ("inactive", "disabled", "1"))
        # apply 쪽: 파일·ACTIVE가 없어도 유닛이 살아 있으면 새 RUN을 거부한다
        self.psk("vpn-gw01", "20261012T1801")
        (self.state / "unit_active").write_text("active\n")
        refused = self.run_cmd("vpn-gw01", "apply", "20261012T1801")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("포워딩 유닛이 남아 있음", refused.stderr)
        self.assertFalse((self.prefix / "root/fds-p2-vpn/20261012T1801").exists(), "상태 폴더를 만들기 전에 거부")

    def test_r4c_firewalld_query_error_is_not_absence(self):
        """리뷰 5467915112 2: query-port/query-forward 조회 오류(rc2)는 실패로 남기고 forwarding 0·ACTIVE 유지, 재시도로 정리."""
        for i, pattern in enumerate(("firewall-cmd --permanent --zone public --query-port 500/udp",
                                     "firewall-cmd --permanent --zone public --query-forward")):
            self.setUp()
            self.host("relay", 0, fw_forward="no")
            run = f"20261012T190{i}"
            self.psk("relay", run)
            self.assertEqual(self.run_cmd("relay", "apply", run).returncode, 0)
            self.assertEqual((sorted(self.st("fw_ports").split()), self.st("fw_forward")),
                             (["4500/udp", "500/udp"], "yes"))
            bad = self.run_cmd("relay", "rollback", run, FAKE_FAIL=pattern, FAKE_FAIL_RC="2")
            ctx = (pattern, bad.stdout, bad.stderr)
            self.assertNotEqual(bad.returncode, 0, ctx)
            self.assertNotIn("ROLLBACK_DONE", bad.stdout, ctx)
            self.assertIn("조회 실패", bad.stderr, ctx)
            self.assertEqual((self.st("ip_forward"), self.active()), ("0", run), ctx)
            again = self.run_cmd("relay", "rollback", run)
            self.assertEqual(again.returncode, 0, (pattern, again.stderr, again.stdout))
            self.assertEqual((self.st("fw_ports"), self.st("fw_forward"), self.active()), ("", "no", ""), pattern)

    def test_r4c_apply_refuses_when_original_firewalld_state_unknown(self):
        self.host("relay", 0, fw_forward="no")
        self.psk("relay", "20261012T1910")
        done = self.run_cmd("relay", "apply", "20261012T1910",
                            FAKE_FAIL="firewall-cmd --permanent --zone public --query-port 4500/udp", FAKE_FAIL_RC="2")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("firewalld 원래 상태 조회 실패", done.stderr)
        self.assertEqual((self.st("fw_ports"), self.st("fw_forward"), self.active()), ("", "no", ""))
        self.assertFalse((self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").exists())

    # ---- 단계 B 리뷰 6163219831 R1: nft 조회 오류를 부재로 보지 않는다 ----
    def stoppost(self, **env):
        unit = (PKG / "systemd/fds-p2-vpn-forward.service").read_text(encoding="utf-8")
        line = next(x for x in unit.splitlines() if x.startswith("ExecStopPost="))
        body = line[len("ExecStopPost=/bin/sh -c '"):-1]
        # systemd가 넘기는 형태로 되돌린다($$→$, %%→%) 그리고 절대경로를 가짜 명령으로 바꾼다.
        body = body.replace("$$", "$").replace("%%", "%")
        body = body.replace("/usr/sbin/", f"{self.bin.as_posix()}/").replace("/usr/bin/grep", "grep")
        full = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}", FAKE_STATE=str(self.state), **env)
        return subprocess.run(["sh", "-c", body], capture_output=True, text=True, env=full)

    def test_r1_stoppost_query_or_delete_error_is_not_success(self):
        self.host("relay", 1)
        (self.state / "nft_table").write_text("present\n")
        for env in ({"FAKE_FAIL": "nft list tables", "FAKE_FAIL_RC": "2"},
                    {"FAKE_FAIL": "nft delete table inet fds_p2_vpn"}):
            (self.state / "ip_forward").write_text("1\n")
            done = self.stoppost(**env)
            self.assertNotEqual(done.returncode, 0, env)
            self.assertEqual((self.st("ip_forward"), self.st("nft_table")), ("0", "present"), env)
        done = self.stoppost()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual((self.st("ip_forward"), self.st("nft_table")), ("0", "absent"))
        again = self.stoppost()
        self.assertEqual(again.returncode, 0, "표가 이미 없으면(조회 성공) 정상 종료")

    def test_r1_apply_refuses_when_nft_inventory_query_fails(self):
        self.host("vpn-gw01", 1, fw_forward="yes")
        self.psk("vpn-gw01", "20261014T1700")
        done = self.run_cmd("vpn-gw01", "apply", "20261014T1700", FAKE_FAIL="nft list tables", FAKE_FAIL_RC="2")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("nft 목록 조회 실패", done.stderr)
        self.assertEqual((self.active(), self.st("ip_forward")), ("", "1"), "호스트를 바꾸기 전에 중단")
        self.assertFalse((self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").exists())
        self.assertEqual(self.gw_file().read_text(), self.GW_ORIG)

    def test_r1_rollback_nft_errors_keep_controls_and_same_run_retry(self):
        for i, (pattern, rc) in enumerate((("nft list tables", "2"), ("nft delete table inet fds_p2_vpn", "1"))):
            self.setUp()
            self.host("vpn-gw01", 1, fw_forward="yes")
            run = f"20261014T171{i}"
            self.psk("vpn-gw01", run)
            self.assertEqual(self.run_cmd("vpn-gw01", "apply", run).returncode, 0)
            # 유닛은 멈췄지만 허용표가 남은 상태(리뷰의 재현 조건)
            (self.state / "unit_active").write_text("inactive\n")
            (self.state / "unit_enabled").write_text("disabled\n")
            self.assertEqual(self.st("nft_table"), "present")
            bad = self.run_cmd("vpn-gw01", "rollback", run, FAKE_FAIL=pattern, FAKE_FAIL_RC=rc)
            ctx = (pattern, bad.stdout, bad.stderr)
            self.assertNotEqual(bad.returncode, 0, ctx)
            self.assertNotIn("ROLLBACK_DONE", bad.stdout, ctx)
            self.assertEqual((self.st("ip_forward"), self.st("nft_table"), self.active()), ("0", "present", run), ctx)
            self.assertTrue((self.prefix / "etc/fds-p2-vpn/forward.nft").exists(), "통제 파일 보존")
            again = self.run_cmd("vpn-gw01", "rollback", run)
            self.assertEqual(again.returncode, 0, (pattern, again.stderr, again.stdout))
            self.assertIn("ROLLBACK_DONE", again.stdout)
            self.assertEqual((self.st("nft_table"), self.active(), self.st("ip_forward")), ("absent", "", "1"))
            self.assertEqual(self.gw_file().read_text(), self.GW_ORIG)

    # ---- 단계 B 리뷰 6163219831 R2: apply 전에 멈춘 RUN의 secrets 정리 ----
    def secrets(self):
        return self.prefix / "etc/ipsec.d/fds-p2-vpn.secrets"

    def receipt(self, run=PSK_RUN):
        return self.prefix / f"root/fds-p2-vpn/psk-receipts/{run}"

    def test_r2_psk_only_is_cleaned_by_psk_clean_not_rollback(self):
        self.host("relay", 0)
        done = self.psk("relay")
        self.assertIn("psk_receipt=", done.stdout)
        text = self.receipt().read_text()
        self.assertIn(f"run={PSK_RUN}", text)
        self.assertNotIn(PSK, text, "기록에 PSK 없음")
        back = self.run_cmd("relay", "rollback", PSK_RUN)
        self.assertNotEqual(back.returncode, 0)
        self.assertIn("state.env 없음", back.stderr)
        clean = self.run_cmd("relay", "psk-clean", PSK_RUN)
        self.assertEqual(clean.returncode, 0, clean.stderr + clean.stdout)
        self.assertIn("PSK_CLEAN_DONE role=relay", clean.stdout)
        self.assertFalse(self.secrets().exists())
        self.assertIn("cleaned_at=", self.receipt().read_text())
        self.assertEqual((self.st("ip_forward"), self.st("nft_table") or "absent"), ("0", "absent"))

    def test_r2_apply_precheck_stop_then_psk_clean(self):
        self.host("vpn-gw01", 1, fw_forward="yes", ipsec_active=True)
        self.psk("vpn-gw01", "20261014T1720")
        done = self.run_cmd("vpn-gw01", "apply", "20261014T1720", FAKE_CHECKCONFIG_FAIL="1")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("conn 문법 검사 실패", done.stderr)
        self.assertTrue(self.secrets().exists(), "사전 검사 중단 뒤 secrets가 남는 경로")
        self.assertEqual(self.active(), "")
        back = self.run_cmd("vpn-gw01", "rollback", "20261014T1720")
        self.assertNotEqual(back.returncode, 0)
        clean = self.run_cmd("vpn-gw01", "psk-clean", "20261014T1720")
        self.assertEqual(clean.returncode, 0, clean.stderr + clean.stdout)
        self.assertFalse(self.secrets().exists())
        rereads = [c for c in self.calls() if "rereadsecrets" in c]
        self.assertEqual(len(rereads), 2, "psk 때 1회 + 삭제 뒤 pluto에서 비우는 1회")
        self.assertEqual((self.st("ip_forward"), self.gw_file().read_text()), ("1", self.GW_ORIG), "호스트 설정 불변")

    def test_r2_refusals_keep_unowned_or_installed_secrets(self):
        self.host("relay", 0)
        foreign = '@x @y : PSK "not-ours"\n'
        self.secrets().write_text(foreign)
        over = self.run_cmd("relay", "psk", PSK_RUN, stdin=f"{PSK}\n{PSK}\n")
        self.assertNotEqual(over.returncode, 0)
        self.assertIn("생성 기록이 없음", over.stderr)
        clean = self.run_cmd("relay", "psk-clean", PSK_RUN)
        self.assertNotEqual(clean.returncode, 0)
        self.assertIn("생성 기록 없음", clean.stderr)
        self.assertEqual(self.secrets().read_text(), foreign, "출처 모르는 secrets는 덮어쓰거나 지우지 않음")
        self.secrets().unlink()
        self.psk("relay", "20261014T1730")
        self.assertEqual(self.run_cmd("relay", "apply", "20261014T1730").returncode, 0)
        busy = self.run_cmd("relay", "psk-clean", PSK_RUN)
        self.assertNotEqual(busy.returncode, 0)
        self.assertIn("rollback", busy.stderr)
        self.assertTrue(self.secrets().exists())
        other = self.run_cmd("relay", "psk", "20261014T1731", stdin=f"{PSK}\n{PSK}\n")
        self.assertNotEqual(other.returncode, 0)
        self.assertIn("다른 RUN", other.stderr)
        rotate = self.run_cmd("relay", "psk", "20261014T1730", stdin=f"{PSK}\n{PSK}\n")
        self.assertEqual(rotate.returncode, 0, rotate.stderr)
        back = self.run_cmd("relay", "rollback", "20261014T1730")
        self.assertEqual(back.returncode, 0, back.stderr + back.stdout)
        self.assertFalse(self.secrets().exists())
        self.assertIn("by=rollback", self.receipt("20261014T1730").read_text())

    def test_r2_psk_clean_stops_on_nft_query_error(self):
        self.host("relay", 0)
        self.psk("relay")
        bad = self.run_cmd("relay", "psk-clean", PSK_RUN, FAKE_FAIL="nft list tables", FAKE_FAIL_RC="2")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("nft 목록 조회 실패", bad.stderr)
        self.assertTrue(self.secrets().exists(), "조회 오류면 secrets 보존")
        self.assertNotIn("cleaned_at=", self.receipt().read_text())

    # ---- PR6 리뷰 5514997984 C1: 현재 secrets의 소유 RUN 결속 ----
    def owner(self):
        path = self.prefix / "root/fds-p2-vpn/psk-receipts/OWNER"
        return path.read_text().strip() if path.exists() else ""

    def test_c1_finished_receipt_cannot_touch_other_runs_secrets(self):
        self.host("relay", 0)
        a, b = "20261014T1800", "20261014T1801"
        self.psk("relay", a)
        self.assertEqual(self.owner(), a)
        self.assertEqual(self.run_cmd("relay", "psk-clean", a).returncode, 0)
        self.assertEqual(self.owner(), "", "정리 완료 뒤 소유 해제")
        self.psk("relay", b)
        stale = self.run_cmd("relay", "psk-clean", a)
        self.assertNotEqual(stale.returncode, 0, "리뷰 재현: 끝난 A 기록으로 B를 지우면 안 됨")
        self.assertIn("이미 정리됨", stale.stderr)
        self.assertTrue(self.secrets().exists())
        self.assertEqual(self.owner(), b)
        reuse = self.run_cmd("relay", "psk", a, stdin=f"{PSK}\n{PSK}\n")
        self.assertNotEqual(reuse.returncode, 0, "끝난 RUN 재사용 거부")
        self.assertIn("이미 정리됨", reuse.stderr)
        other = self.run_cmd("relay", "psk", "20261014T1802", stdin=f"{PSK}\n{PSK}\n")
        self.assertNotEqual(other.returncode, 0, "다른 RUN이 소유한 secrets를 덮어쓰지 않음")
        self.assertIn(f"소유 RUN은 {b}", other.stderr)
        self.assertEqual(self.owner(), b)

    def test_c1_apply_requires_psk_owner_run(self):
        self.host("vpn-gw01", 1, fw_forward="yes")
        self.psk("vpn-gw01", "20261014T1810")
        calls_before = len(self.calls())
        done = self.run_cmd("vpn-gw01", "apply", "20261014T1811")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("소유 RUN", done.stderr)
        self.assertEqual(self.active(), "")
        self.assertFalse((self.prefix / "root/fds-p2-vpn/20261014T1811").exists(), "상태 폴더도 만들지 않음")
        self.assertFalse(any(c.startswith(("systemctl restart", "firewall-cmd --permanent --zone public --add"))
                             for c in self.calls()[calls_before:]))
        ok = self.run_cmd("vpn-gw01", "apply", "20261014T1810")
        self.assertEqual(ok.returncode, 0, ok.stderr + ok.stdout)
        back = self.run_cmd("vpn-gw01", "rollback", "20261014T1810")
        self.assertEqual(back.returncode, 0, back.stderr + back.stdout)
        self.assertEqual(self.owner(), "", "rollback이 소유 해제")
        self.assertIn("by=rollback", self.receipt("20261014T1810").read_text())

    def test_c1_failed_write_keeps_owner_for_same_run_cleanup(self):
        self.host("relay", 0)
        run = "20261014T1820"
        bad = self.run_cmd("relay", "psk", run, stdin=f"{PSK}\n{PSK}\n", FAKE_FAIL="chown *")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("secrets 저장 실패", bad.stderr)
        self.assertFalse(self.secrets().exists())
        self.assertEqual(self.owner(), run, "파일 쓰기 전에 소유를 남겨 정리 경로를 잃지 않음")
        self.assertEqual(list((self.prefix / "etc/ipsec.d").glob(".fds-p2-vpn.secrets.*")), [])
        retry = self.run_cmd("relay", "psk", run, stdin=f"{PSK}\n{PSK}\n")
        self.assertEqual(retry.returncode, 0, "같은 RUN 재시도 허용")
        clean = self.run_cmd("relay", "psk-clean", run)
        self.assertEqual(clean.returncode, 0, clean.stderr + clean.stdout)
        self.assertEqual((self.secrets().exists(), self.owner()), (False, ""))

    # ---- PR6 리뷰 5514997984 C2: ipsec 상태 조회 오류는 정리 완료가 아님 ----
    def test_c2_ipsec_state_error_or_transition_keeps_secrets(self):
        run = "20261014T1830"
        for env, state in (({"FAKE_FAIL": "systemctl is-active ipsec", "FAKE_FAIL_RC": "42"}, "active"),
                           ({}, "activating"), ({}, "")):
            self.setUp()
            self.host("vpn-gw01", 1, fw_forward="yes", ipsec_active=True)
            self.psk("vpn-gw01", run)
            (self.state / "ipsec").write_text(f"{state}\n")
            bad = self.run_cmd("vpn-gw01", "psk-clean", run, **env)
            ctx = (env, state, bad.stdout, bad.stderr)
            self.assertNotEqual(bad.returncode, 0, ctx)
            self.assertIn("ipsec 상태 확인 불가", bad.stderr, ctx)
            self.assertNotIn("PSK_CLEAN_DONE", bad.stdout, ctx)
            self.assertTrue(self.secrets().exists(), ctx)
            self.assertEqual(self.owner(), run, ctx)
            self.assertNotIn("cleaned_at=", self.receipt(run).read_text(), ctx)

    def test_c2_active_ipsec_conn_loaded_refused_and_reread_failure_retry(self):
        run = "20261014T1840"
        self.host("vpn-gw01", 1, fw_forward="yes", ipsec_active=True)
        self.psk("vpn-gw01", run)
        (self.state / "conn_added").touch()
        loaded = self.run_cmd("vpn-gw01", "psk-clean", run)
        self.assertNotEqual(loaded.returncode, 0)
        self.assertIn("적재돼 있음", loaded.stderr)
        self.assertTrue(self.secrets().exists())
        (self.state / "conn_added").unlink()
        bad = self.run_cmd("vpn-gw01", "psk-clean", run, FAKE_FAIL="ipsec rereadsecrets")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("rereadsecrets 실패", bad.stderr)
        self.assertFalse(self.secrets().exists())
        self.assertEqual(self.owner(), run, "pluto 정리 미확인이면 소유 유지")
        self.assertNotIn("cleaned_at=", self.receipt(run).read_text())
        again = self.run_cmd("vpn-gw01", "psk-clean", run)
        self.assertEqual(again.returncode, 0, again.stderr + again.stdout)
        self.assertEqual(self.owner(), "")
        self.assertIn("by=psk-clean", self.receipt(run).read_text())
        inactive = "20261014T1841"
        (self.state / "ipsec").write_text("inactive\n")
        self.psk("vpn-gw01", inactive)
        calls_before = len(self.calls())
        clean = self.run_cmd("vpn-gw01", "psk-clean", inactive)
        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertFalse(any("rereadsecrets" in c for c in self.calls()[calls_before:]), "inactive면 reread 불필요")

    def test_c2_rollback_rereads_when_ipsec_stays_active(self):
        run = "20261014T1850"
        self.host("vpn-gw01", 1, fw_forward="yes", ipsec_active=True)
        (self.state / "ipsec_enabled").write_text("enabled\n")
        self.psk("vpn-gw01", run)
        self.assertEqual(self.run_cmd("vpn-gw01", "apply", run).returncode, 0)
        bad = self.run_cmd("vpn-gw01", "rollback", run, FAKE_FAIL="ipsec rereadsecrets")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("ROLLBACK_INCOMPLETE", bad.stderr)
        self.assertEqual((self.st("ip_forward"), self.active()), ("0", run))
        calls_before = len(self.calls())
        back = self.run_cmd("vpn-gw01", "rollback", run)
        self.assertEqual(back.returncode, 0, back.stderr + back.stdout)
        self.assertEqual(self.st("ipsec"), "active", "apply 전부터 떠 있던 ipsec은 유지")
        self.assertTrue(any("rereadsecrets" in c for c in self.calls()[calls_before:]), "지운 PSK를 pluto에서도 비움")
        self.assertEqual(self.owner(), "")

    # ---- PR6 재검토 5515275797 C1 잔여: 끝난 옛 RUN의 rollback은 첫 호스트 변경 전에 멈춤 ----
    MUTATING = ("sysctl -w", "firewall-cmd --reload", "firewall-cmd --permanent --zone public --add",
                "firewall-cmd --permanent --zone public --remove", "firewall-cmd --zone public --add",
                "firewall-cmd --zone public --remove", "systemctl stop", "systemctl disable", "systemctl enable",
                "systemctl start", "systemctl restart", "systemctl daemon-reload", "ipsec delete",
                "ipsec rereadsecrets", "nft delete", "nft -f")

    def mutations(self, since):
        return [c for c in self.calls()[since:] if c.startswith(self.MUTATING)]

    def test_c1_old_rollback_cannot_touch_next_runs_secrets(self):
        self.host("vpn-gw01", 1, fw_forward="yes", ipsec_active=True)
        (self.state / "ipsec_enabled").write_text("enabled\n")
        a, b = "20261014T1800", "20261014T1801"
        self.psk("vpn-gw01", a)
        self.assertEqual(self.run_cmd("vpn-gw01", "apply", a).returncode, 0)
        bad = self.run_cmd("vpn-gw01", "rollback", a, FAKE_FAIL="nft list tables", FAKE_FAIL_RC="2")
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual((self.owner(), self.active()), (a, a), "미완료 rollback은 소유·ACTIVE 유지")
        back = self.run_cmd("vpn-gw01", "rollback", a)
        self.assertEqual(back.returncode, 0, back.stderr + back.stdout)
        self.assertEqual(self.owner(), "")
        self.psk("vpn-gw01", b)
        fwd, gw = self.st("ip_forward"), self.gw_file().read_text()
        for _ in range(2):
            calls_before = len(self.calls())
            old = self.run_cmd("vpn-gw01", "rollback", a)
            self.assertNotEqual(old.returncode, 0, "리뷰 재현: 끝난 A의 rollback 재실행")
            self.assertIn("이미 정리됨", old.stderr)
            self.assertNotIn("ROLLBACK_DONE", old.stdout)
            self.assertEqual(self.mutations(calls_before), [], "첫 호스트 변경 전에 멈춤")
            self.assertTrue(self.secrets().exists(), "B secrets 보존")
            self.assertEqual(self.owner(), b)
            self.assertEqual((self.st("ip_forward"), self.gw_file().read_text()), (fwd, gw))
        self.assertEqual(self.run_cmd("vpn-gw01", "psk-clean", b).returncode, 0)
        calls_before = len(self.calls())
        again = self.run_cmd("vpn-gw01", "rollback", a)
        self.assertNotEqual(again.returncode, 0, "다음 RUN이 없어도 끝난 RUN 반복 호출은 거부")
        self.assertEqual(self.mutations(calls_before), [])

    def test_c1_rollback_refuses_run_without_ownership(self):
        self.host("relay", 0)
        a = "20261014T1805"
        self.psk("relay", a)
        self.assertEqual(self.run_cmd("relay", "apply", a).returncode, 0)
        owner_file = self.prefix / "root/fds-p2-vpn/psk-receipts/OWNER"
        owner_file.unlink()
        calls_before = len(self.calls())
        bad = self.run_cmd("relay", "rollback", a)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("소유 RUN('없음')", bad.stderr)
        self.assertEqual(self.mutations(calls_before), [], "소유 확인 없이 자동 통과하지 않음")
        self.assertEqual(self.active(), a)

    def owner_release_blocked(self, how):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root는 권한으로 쓰기 실패를 만들 수 없음")
        self.host("vpn-gw01", 1, fw_forward="yes", ipsec_active=True)
        (self.state / "ipsec_enabled").write_text("enabled\n")
        a = "20261014T1860"
        self.psk("vpn-gw01", a)
        self.assertEqual(self.run_cmd("vpn-gw01", "apply", a).returncode, 0)
        target = self.receipt(a) if how == "receipt" else self.receipt(a).parent
        mode = target.stat().st_mode
        os.chmod(target, 0o444 if how == "receipt" else 0o555)
        try:
            back = self.run_cmd("vpn-gw01", "rollback", a)
        finally:
            os.chmod(target, mode)
        self.assertEqual(back.returncode, 3, back.stderr + back.stdout)
        self.assertIn("owner_release=INCOMPLETE", back.stdout)
        self.assertIn("OWNER_RELEASE_INCOMPLETE", back.stderr)
        self.assertEqual((self.st("ip_forward"), self.active(), self.owner()), ("1", "", a), "호스트 원복 완료·소유 유지")
        self.assertFalse(self.secrets().exists())
        calls_before = len(self.calls())
        old = self.run_cmd("vpn-gw01", "rollback", a)
        self.assertNotEqual(old.returncode, 0)
        self.assertIn("psk-clean", old.stderr)
        self.assertEqual(self.mutations(calls_before), [], "원복을 다시 하지 않음")
        nxt = self.run_cmd("vpn-gw01", "psk", "20261014T1861", stdin=f"{PSK}\n{PSK}\n")
        self.assertNotEqual(nxt.returncode, 0, "소유가 남아 새 RUN psk는 멈춤")
        fin = self.run_cmd("vpn-gw01", "psk-clean", a)
        self.assertEqual(fin.returncode, 0, fin.stderr + fin.stdout)
        self.assertIn("소유 기록 정리만 재시도함", fin.stdout)
        self.assertEqual(self.owner(), "")
        self.assertEqual(self.receipt(a).read_text().count("cleaned_at="), 1)
        self.assertEqual(self.st("ip_forward"), "1")
        self.psk("vpn-gw01", "20261014T1861")
        self.assertEqual(self.owner(), "20261014T1861")

    def test_c1_rollback_receipt_write_failure_then_psk_clean_finishes(self):
        self.owner_release_blocked("receipt")

    @unittest.skipIf(os.name == "nt", "디렉터리 쓰기 금지로 파일 삭제 실패를 만들 수 없음(Windows)")
    def test_c1_rollback_owner_remove_failure_then_psk_clean_finishes(self):
        self.owner_release_blocked("dir")


@unittest.skipUnless(os.environ.get("P2VPN_CONTAINER_IT") == "1" and shutil.which("docker"),
                     "P2VPN_CONTAINER_IT=1 과 docker 필요 — CI workflow에서 실행")
class DistroSyntaxTests(unittest.TestCase):
    """배포판 Libreswan·nftables로 실제 문법을 검사한다."""

    def check(self, image, role, harbor):
        cmd = (
            "set -euo pipefail; dnf -y -q install libreswan nftables > /dev/null; "
            "ipsec --version | head -1; rpm -q libreswan nftables; "
            f"FDS_HARBOR={harbor} RELAY_EIP={TEST_EIP} bash /pkg/p2vpn.sh {role} render /tmp/out; "
            "ipsec addconn --checkconfig --config /tmp/out/ipsec-check.conf; echo CHECKCONFIG_RC=$?; "
            "nft -c -f /tmp/out/forward.nft; echo NFT_RC=$?"
        )
        done = subprocess.run(["docker", "run", "--rm", "--cap-add", "NET_ADMIN", "-v", f"{PKG}:/pkg:ro",
                               IMAGES[image], "bash", "-c", cmd], capture_output=True, text=True, timeout=600)
        print(f"--- {image} {role} harbor={harbor}\n{done.stdout}{done.stderr[-2000:]}")
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        self.assertIn("CHECKCONFIG_RC=0", done.stdout)
        self.assertIn("NFT_RC=0", done.stdout)
        self.assertNotRegex(done.stdout + done.stderr, r"(?i)obsolete keyword|unknown keyword|deprecated|keyword ignored",
                            "버전별로 무시·폐기된 키워드가 없어야 한다")

    def test_relay_on_stream9(self):
        for harbor in ("off", "on"):
            self.check("stream9", "relay", harbor)

    def test_vpn_gw01_on_stream10(self):
        for harbor in ("off", "on"):
            self.check("stream10", "vpn-gw01", harbor)


if __name__ == "__main__":
    unittest.main()
