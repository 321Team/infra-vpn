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
# ROSA Pod·Service는 §1.2 설계 Freeze 채택값(2026-10-19)
ROSA_POD, ROSA_SERVICE, ROSA_HOST_PREFIX = "10.128.0.0/14", "172.30.0.0/16", "/23"
FIXED = [ONPREM, "10.250.10.0/24", "192.168.10.0/24", "10.244.0.0/16", "10.96.0.0/12", VPC, ROSA_POD, ROSA_SERVICE]
SUBNETS = ["10.20.10.0/24", "10.20.20.0/24", "10.20.30.0/24", "10.20.110.0/24"]


def net(c):
    return ipaddress.ip_network(c)


def setting(text, key):
    m = re.search(rf"^\s*{key}=(\S+)\s*$", text, re.M)
    return m.group(1)


def minutes(value):
    m = re.fullmatch(r"(\d+)([mh])", value)
    return int(m.group(1)) * (60 if m.group(2) == "h" else 1)


def fmt(mins):
    total_seconds = round(mins * 60)
    hours, rest = divmod(total_seconds, 3600)
    minutes_part, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h{minutes_part:02d}m" + (f"{secs:02d}s" if secs else "")
    return f"{minutes_part}분" + (f"{secs}초" if secs else "")


def rekey_range(role, life_key):
    life = minutes(setting(CONF[role], life_key))
    margin = minutes(setting(CONF[role], "rekeymargin"))
    assert setting(CONF[role], "rekeyfuzz") == "100%"
    # Libreswan v4.15/v5.4 rekeyfuzz.c fuzz_rekey_margin(): 개시자는 margin×(1~1+fuzz), 응답자는 margin/2.
    # 이 계약의 정상 역할: vpn-gw01 개시자, Relay 응답자(auto=add).
    if role == "relay":
        return life - margin / 2, life - margin / 2
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

    def test_rosa_adopted_blocks_stay_out_of_tunnel_selectors(self):
        for c in (ROSA_POD, ROSA_SERVICE):
            for sel in (ONPREM, VPC):
                self.assertFalse(net(c).overlaps(net(sel)), f"{c} overlaps selector {sel}")
        self.assertIn(f"host prefix `{ROSA_HOST_PREFIX}`", DOC)
        # 이 Pod CIDR에서 /23 노드 블록이 실제로 나뉘는지(prefix 길이 관계)
        self.assertLess(net(ROSA_POD).prefixlen, int(ROSA_HOST_PREFIX.lstrip("/")))

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
                if lo == hi:
                    text = fmt(lo)
                elif lo < 60:
                    text = f"{lo}~{hi}분"
                else:
                    text = f"{fmt(lo)}~{fmt(hi)}"
                self.assertIn(f"**{text}**", DOC, f"{role} {key}")

    def test_responder_uses_half_margin(self):
        self.assertEqual(rekey_range("relay", "salifetime"), (55.5, 55.5))
        self.assertEqual(rekey_range("relay", "ikelifetime"), (475.5, 475.5))
        self.assertIn("**55분30초**", DOC)
        self.assertIn("**7h55m30s**", DOC)

    def test_rekey_success_split_by_type(self):
        self.assertIn("**Child rekey:**", DOC)
        self.assertIn("**IKE rekey:**", DOC)
        self.assertIn("RFC 7296 §2.8", DOC)

    def test_normal_timer_initiator_rekeys_first(self):
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
