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
    # quay.io/centos/centos 고정 digest(2026-10-07 빌드). Relay AMI는 Stream 9, vpn-gw01은 Stream 10.
    "stream9": "quay.io/centos/centos@sha256:33346f5fe280763eb78e85f968ad52bc2b2013369de85403f67e802db98ed243",
    "stream10": "quay.io/centos/centos@sha256:e664412637fcadb7d9eef7da6cc48c29cd69fb977d27c871ec3c54d95c91ace9",
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
        # rekey 시점 = 수명 - margin×(1+fuzz). vpn-gw01의 가장 늦은 rekey가 Relay의 가장 이른 rekey보다 앞서야 한다.
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

    def host(self, role, ip_forward, fw_forward="no", ports=()):
        (self.state / "ip_forward").write_text(f"{ip_forward}\n")
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

    def psk(self, role):
        done = self.run_cmd(role, "psk", stdin=f"{PSK}\n{PSK}\n")
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
        crlf = self.run_cmd("relay", "psk", stdin=f"{PSK}\r\n{PSK}\r\n")
        self.assertEqual(crlf.returncode, 0, crlf.stderr)
        self.assertEqual(secrets.read_bytes(), f'@fds-vpn-gw01 @fds-aws-relay01 : PSK "{PSK}"\n'.encode(),
                         "붙여넣기의 줄 끝 CR은 지운다")
        self.assertEqual(list((self.prefix / "etc/ipsec.d").glob(".fds-p2-vpn.secrets.*")), [], "임시 파일 남김 없음")
        for bad, msg in ((f"{PSK}\n{PSK}x\n", "두 입력이 다름"), ("short\nshort\n", "32자 이상"),
                         ('a"' + "b" * 40 + '\n' + 'a"' + "b" * 40 + "\n", "따옴표"),
                         ("a\x1b" + "b" * 40 + "\n" + "a\x1b" + "b" * 40 + "\n", "제어 문자")):
            failed = self.run_cmd("relay", "psk", stdin=bad)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn(msg, failed.stderr)
        self.assertEqual(secrets.read_text(), f'@fds-vpn-gw01 @fds-aws-relay01 : PSK "{PSK}"\n', "실패 시 기존 유지")

    def test_relay_apply_then_rollback_restores_everything(self):
        self.host("relay", 0, fw_forward="no")
        self.psk("relay")
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
        self.psk("vpn-gw01")
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
        self.psk("relay")
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
                self.psk("relay")
            done = self.run_cmd("relay", "apply", f"20261012T110{i}", **env)
            self.assertNotEqual(done.returncode, 0, env)
            self.assertIn(msg, done.stderr)
            self.assertFalse((self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").exists(), "설치 전 중단")
            self.assertEqual((self.st("ip_forward"), self.st("fw_ports")), ("0", ""))

    def test_unit_failure_keeps_forwarding_off(self):
        self.host("relay", 0)
        self.psk("relay")
        done = self.run_cmd("relay", "apply", "20261012T1200", FAKE_UNIT_FAIL="1")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("포워딩은 꺼진 채로 둔다", done.stderr)
        self.assertEqual(self.st("ip_forward"), "0")
        self.assertFalse((self.state / "conn_added").exists(), "포워딩이 없으면 conn도 등록하지 않는다")

    def test_identity_guard_and_status_redaction(self):
        self.host("relay", 0)
        self.ip = "10.1.93.51"
        wrong = self.run_cmd("relay", "psk", stdin=f"{PSK}\n{PSK}\n")
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
        self.psk("vpn-gw01")
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
        self.psk("vpn-gw01")
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
            self.psk("vpn-gw01")
            run = f"20261012T132{i}"
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
        self.psk("vpn-gw01")
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
        self.psk("relay")
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
        self.psk("vpn-gw01")
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
        self.psk("relay")
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
                self.psk(role)
                run = f"20261012T16{n:02d}"
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
        self.psk("relay")
        self.assertEqual(self.run_cmd("relay", "apply", "20261012T1700").returncode, 0)
        (self.state / "conn_added").unlink()  # 조회 성공·등록 없음
        done = self.run_cmd("relay", "rollback", "20261012T1700")
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)
        self.assertIn("conn: 등록 없음(조회 확인)", done.stdout)
        self.setUp()
        self.host("relay", 0)
        self.psk("relay")
        self.assertEqual(self.run_cmd("relay", "apply", "20261012T1701").returncode, 0)
        (self.state / "ipsec").write_text("inactive\n")  # ipsec.service가 내려가 있으면 conn 적재 없음
        done = self.run_cmd("relay", "rollback", "20261012T1701")
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)
        self.assertIn("ipsec.service: inactive", done.stdout)

    def test_r4c_unit_left_running_without_files_is_stopped_and_blocks_apply(self):
        """리뷰 5467915112 1: 파일이 없어도 active/enabled 유닛은 성공으로 보지 않는다."""
        self.host("vpn-gw01", 1, fw_forward="yes")
        self.psk("vpn-gw01")
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
        self.psk("vpn-gw01")
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
            self.psk("relay")
            run = f"20261012T190{i}"
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
        self.psk("relay")
        done = self.run_cmd("relay", "apply", "20261012T1910",
                            FAKE_FAIL="firewall-cmd --permanent --zone public --query-port 4500/udp", FAKE_FAIL_RC="2")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("firewalld 원래 상태 조회 실패", done.stderr)
        self.assertEqual((self.st("fw_ports"), self.st("fw_forward"), self.active()), ("", "no", ""))
        self.assertFalse((self.prefix / "etc/ipsec.d/fds-p2-vpn.conf").exists())


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
