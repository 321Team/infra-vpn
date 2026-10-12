"""P2-VPN-01 (#37) NETWORK.md 정적 시험.

- §1 CIDR 대장: 확정 대역끼리 겹치지 않는지, VPC 서브넷이 VPC 안에서 서로 겹치지 않는지, 문서·conn 템플릿과 같은지.
- §3 rekey: 템플릿 수명·rekeymargin으로 계산한 rekey 범위가 문서 표와 같고 vpn-gw01이 항상 먼저인지.
서버·AWS·클러스터에 접속하지 않는다.
"""
from pathlib import Path
import ipaddress
import itertools
import re
import unittest

PKG = Path(__file__).resolve().parents[1]
DOC = (PKG / "NETWORK.md").read_text(encoding="utf-8")
CONF = {role: (PKG / "conf" / f"{role}.conf.tmpl").read_text(encoding="utf-8") for role in ("vpn-gw01", "relay")}

ONPREM = "10.1.93.0/24"
VPC = "10.20.0.0/16"
# §1.1 최상위 확정 대역(출처는 NETWORK.md 표)
FIXED = [ONPREM, "10.250.10.0/24", "192.168.10.0/24", "10.244.0.0/16", "10.96.0.0/12", VPC]
SUBNETS = ["10.20.10.0/24", "10.20.20.0/24", "10.20.30.0/24", "10.20.110.0/24"]
ROSA_DEFAULT_CANDIDATES = ["10.128.0.0/14", "172.30.0.0/16"]  # §1.2: 문서 기본값 후보, 확정 아님


def net(c):
    return ipaddress.ip_network(c)


def setting(text, key):
    m = re.search(rf"^\s*{key}=(\S+)\s*$", text, re.M)
    return m.group(1)


def minutes(value):
    m = re.fullmatch(r"(\d+)([mh])", value)
    return int(m.group(1)) * (60 if m.group(2) == "h" else 1)


def fmt(mins):
    return f"{mins}분" if mins < 60 else f"{mins // 60}h{mins % 60:02d}m"


def rekey_range(role, life_key):
    life = minutes(setting(CONF[role], life_key))
    margin = minutes(setting(CONF[role], "rekeymargin"))
    assert setting(CONF[role], "rekeyfuzz") == "100%"
    return life - 2 * margin, life - margin


class CidrLedgerTests(unittest.TestCase):
    def test_fixed_blocks_do_not_overlap(self):
        for a, b in itertools.combinations(FIXED, 2):
            self.assertFalse(net(a).overlaps(net(b)), f"{a} overlaps {b}")

    def test_vpc_subnets_inside_vpc_and_disjoint(self):
        for s in SUBNETS:
            self.assertTrue(net(s).subnet_of(net(VPC)), s)
        for a, b in itertools.combinations(SUBNETS, 2):
            self.assertFalse(net(a).overlaps(net(b)), f"{a} overlaps {b}")

    def test_rosa_default_candidates_avoid_fixed_blocks(self):
        for c in ROSA_DEFAULT_CANDIDATES:
            for f in FIXED:
                self.assertFalse(net(c).overlaps(net(f)), f"{c} overlaps {f}")
            self.assertIn(f"`{c}`", DOC)

    def test_doc_lists_every_block(self):
        for c in FIXED + SUBNETS:
            self.assertIn(f"`{c}`", DOC, c)

    def test_selectors_match_templates(self):
        self.assertEqual(setting(CONF["vpn-gw01"], "leftsubnet"), ONPREM)
        self.assertEqual(setting(CONF["vpn-gw01"], "rightsubnet"), VPC)
        self.assertEqual(setting(CONF["relay"], "leftsubnet"), VPC)
        self.assertEqual(setting(CONF["relay"], "rightsubnet"), ONPREM)
        self.assertIn(f"`{ONPREM} <-> {VPC}`", DOC)


class RekeyProcedureTests(unittest.TestCase):
    def test_doc_table_matches_template_math(self):
        for role in ("vpn-gw01", "relay"):
            for key in ("salifetime", "ikelifetime"):
                lo, hi = rekey_range(role, key)
                if lo < 60:
                    text = f"{lo}~{hi}분"
                else:
                    text = f"{fmt(lo)}~{fmt(hi)}"
                self.assertIn(f"**{text}**", DOC, f"{role} {key}")

    def test_initiator_always_rekeys_first(self):
        for key in ("salifetime", "ikelifetime"):
            _, gw_hi = rekey_range("vpn-gw01", key)
            relay_lo, _ = rekey_range("relay", key)
            self.assertLess(gw_hi, relay_lo, key)

    def test_roles_and_liveness_documented(self):
        self.assertEqual(setting(CONF["vpn-gw01"], "auto"), "start")
        self.assertEqual(setting(CONF["relay"], "auto"), "add")
        for role in CONF:
            self.assertEqual(setting(CONF[role], "dpddelay"), "30s")
            self.assertEqual(setting(CONF[role], "retransmit-timeout"), "120s")
        self.assertIn("`dpddelay=30s`, `retransmit-timeout=120s`", DOC)

    def test_no_secret_material(self):
        self.assertNotRegex(DOC, r"0x[0-9a-fA-F]{16,}")
        self.assertNotRegex(DOC, r"(?i)psk\s*[:=]\s*\S{8,}")


if __name__ == "__main__":
    unittest.main()
