"""Tests for decodash.analyze and decodash.knowledge.

All data here is made up and SPEC-shaped. Nothing touches the network.
"""

from __future__ import annotations

import copy
import json
import re
import unittest

from decodash import analyze as analyze_mod
from decodash import knowledge
from decodash.analyze import analyze

BANDS = ("band2_4", "band5", "band6")
SEVERITIES = ("critical", "high", "medium", "low", "good")
IMPACTS = ("big", "medium", "small")
CATEGORIES = ("mesh", "wifi", "internet", "devices", "settings", "this computer")
BOTTLENECKS = ("internet plan", "wifi signal", "mesh backhaul", "bufferbloat",
               "device", "dns", "none found", "not enough data")
FINDING_KEYS = ("id", "severity", "category", "title", "what_it_means", "how_to_fix", "impact", "evidence")
CHECK_KEYS = ("id", "title", "status", "detail", "how")


def _bandmap(**values):
    out = {b: None for b in BANDS}
    out.update(values)
    return out


def _node(name, mac, role="satellite", parent=None, backhaul="wired", bands=None,
          dbm=None, bars=None, rx=None, tx=None, fw="1.1.2 Build 20250101 Rel. 1000",
          clients=3, online=True, inet=True, model="BE65"):
    return {
        "mac": mac,
        "name": name,
        "model": model,
        "hw_version": "1.0",
        "fw_version": fw,
        "ip": None,
        "role": role,
        "online": online,
        "internet_online": inet,
        "parent_mac": parent if role == "satellite" else None,
        "backhaul": "n/a" if role == "main" else backhaul,
        "backhaul_bands": list(bands or []),
        "signal_dbm": _bandmap(**(dbm or {})),
        "signal_bars": _bandmap(**(bars or {})),
        "rx_rate_mbps": _bandmap(**(rx or {})),
        "tx_rate_mbps": _bandmap(**(tx or {})),
        "backhaul_speed_mbps": None,
        "backhaul_max_mbps": None,
        "wired_ports": 4,
        "client_count": clients,
    }


MAIN_MAC = "AA:00:00:00:00:01"
KIDS_MAC = "AA:00:00:00:00:02"
OFFICE_MAC = "AA:00:00:00:00:03"


def _client(i, band="band5", node=MAIN_MAC):
    return {"mac": "CC:00:00:00:00:%02X" % i, "name": "Device %d" % i, "ip": "192.168.68.%d" % (100 + i),
            "online": True, "band": band, "interface": "main", "node_mac": node,
            "down_kbps": 10.0, "up_kbps": 5.0}


def _band(enabled=True, width=160, channel=36, mode="11be", hidden=False):
    return {"enabled": enabled, "channel": channel, "channel_width": "EHT%d" % width if width else None,
            "width_mhz": width, "mode": mode, "backhaul_channel": channel, "hidden": hidden}


def perfect_snapshot():
    """A network with nothing wrong: wired BE65 mesh, fast Wi-Fi, full plan speed."""
    clients = []
    for i in range(4):
        clients.append(_client(i, "band5", MAIN_MAC))
    for i in range(4, 7):
        clients.append(_client(i, "band6", KIDS_MAC))
    for i in range(7, 9):
        clients.append(_client(i, "band2_4", OFFICE_MAC))
    clients.append(_client(9, "band5", OFFICE_MAC))
    return {
        "generated_at": "2026-11-25T22:29:00+00:00",
        "demo": False,
        "settings": {"deco_host": "192.168.68.1", "plan_down_mbps": 500.0, "plan_up_mbps": 50.0, "room": "Desk"},
        "deco": {
            "fetched_at": "2026-11-25T22:28:00+00:00",
            "nodes": [
                _node("Living Room", MAIN_MAC, role="main", clients=4),
                _node("Kids", KIDS_MAC, parent=MAIN_MAC, backhaul="wired", clients=3),
                _node("Office", OFFICE_MAC, parent=MAIN_MAC, backhaul="wired", clients=3),
            ],
            "clients": clients,
            "wifi": {
                "bands": {
                    "band2_4": _band(width=20, channel=6, mode="11ax"),
                    "band5": _band(width=160, channel=36),
                    "band6": _band(width=320, channel=37),
                },
                "guest_enabled": False,
                "iot_enabled": True,
                "mlo_enabled": True,
                "same_ssid_all_bands": True,
            },
            "wan": {
                "wan_ip": "81.2.69.160", "wan_mask": "255.255.255.0", "gateway": "81.2.69.1",
                "dial_type": "dynamic_ip", "dns": ["1.1.1.1"], "auto_dns": False,
                "lan_ip": "192.168.68.1", "lan_mask": "255.255.252.0",
                "double_nat": False, "cgnat": False, "ipv6_enabled": True,
            },
            "performance": {"cpu_pct": 12.0, "mem_pct": 40.0},
            "errors": {},
            "raw": {},
        },
        "deco_error": None,
        "link": {
            "os": "macos", "type": "wifi", "interface": "en0", "ssid": "Home", "bssid": None,
            "band": "6GHz", "channel": 37, "width_mhz": 320, "phy": "802.11be", "wifi_gen": 7,
            "rssi_dbm": -48, "noise_dbm": -95, "snr_db": 47, "signal_pct": None,
            "tx_rate_mbps": 2882.0, "rx_rate_mbps": 2400.0, "error": None,
        },
        "latency": {
            "gateway": {"name": "Your Deco", "host": "192.168.68.1", "port": 80,
                        "samples_ms": [2.0, 2.5, 3.0], "median_ms": 2.5, "p90_ms": 3.0,
                        "jitter_ms": 0.5, "loss_pct": 0.0},
            "internet": [
                {"name": "Cloudflare", "host": "1.1.1.1", "port": 443, "samples_ms": [12.0, 13.0],
                 "median_ms": 12.5, "p90_ms": 13.0, "jitter_ms": 1.0, "loss_pct": 0.0},
                {"name": "Google", "host": "8.8.8.8", "port": 443, "samples_ms": [14.0, 15.0],
                 "median_ms": 14.5, "p90_ms": 15.0, "jitter_ms": 1.0, "loss_pct": 0.0},
            ],
            "measured_at": "2026-11-25T22:28:30+00:00", "error": None,
        },
        "speed": {
            "down_mbps": 480.0, "up_mbps": 48.0, "idle_latency_ms": 12.0,
            "loaded_latency_down_ms": 15.0, "loaded_latency_up_ms": 14.0,
            "bufferbloat_ms": 3.0, "bufferbloat_grade": "A+",
            "server": "speed.cloudflare.com", "duration_s": 16.0,
            "measured_at": "2026-11-25T22:28:40+00:00", "error": None,
        },
        "dns": {"median_ms": 14.0, "samples": [{"host": "example.com", "ms": 14.0, "ok": True}],
                "resolvers": ["192.168.68.1"], "measured_at": "2026-11-25T22:28:50+00:00", "error": None},
        "history": [
            {"room": "Living Room", "at": "2026-11-25T20:00:00+00:00", "down_mbps": 490.0, "up_mbps": 49.0,
             "latency_ms": 12.0, "gateway_latency_ms": 2.0, "rssi_dbm": -45, "band": "6GHz", "width_mhz": 320,
             "phy": "802.11be", "bssid": None, "node_name": "Living Room"},
            {"room": "Bedroom", "at": "2026-11-25T20:05:00+00:00", "down_mbps": 450.0, "up_mbps": 47.0,
             "latency_ms": 13.0, "gateway_latency_ms": 3.0, "rssi_dbm": -55, "band": "5GHz", "width_mhz": 160,
             "phy": "802.11be", "bssid": None, "node_name": "Kids"},
        ],
    }


def wireless_sat(snap, name="Kids", mac=KIDS_MAC, parent=MAIN_MAC, bands=("band5",), dbm=None,
                 bars=None, rx=None, tx=None):
    """Turn one satellite in ``snap`` into a wireless-backhaul satellite."""
    for n in snap["deco"]["nodes"]:
        if n["mac"] == mac:
            n["name"] = name
            n["backhaul"] = "wireless"
            n["backhaul_bands"] = list(bands)
            n["parent_mac"] = parent
            n["signal_dbm"] = _bandmap(**(dbm or {}))
            n["signal_bars"] = _bandmap(**(bars or {}))
            n["rx_rate_mbps"] = _bandmap(**(rx or {}))
            n["tx_rate_mbps"] = _bandmap(**(tx or {}))
    return snap


def by_id(result):
    out = {}
    for f in result["findings"]:
        out.setdefault(f["id"], f)
    return out


class AnalyzeTestCase(unittest.TestCase):
    def assertFinding(self, result, fid, severity=None):
        found = by_id(result)
        self.assertIn(fid, found, "expected %s in %s" % (fid, sorted(found)))
        if severity is not None:
            self.assertEqual(found[fid]["severity"], severity, fid)
        return found[fid]

    def assertNoFinding(self, result, fid):
        self.assertNotIn(fid, by_id(result))

    def assertWellFormed(self, result):
        for key in ("score", "grade", "headline", "bottleneck", "findings", "checklist", "data_coverage"):
            self.assertIn(key, result)
        self.assertIn(result["bottleneck"], BOTTLENECKS)
        self.assertIsInstance(result["headline"], str)
        self.assertTrue(result["headline"].strip())
        if result["score"] is None:
            self.assertIsNone(result["grade"])
        else:
            self.assertIsInstance(result["score"], int)
            self.assertTrue(5 <= result["score"] <= 100)
            self.assertIn(result["grade"], ("A", "B", "C", "D", "F"))
        for f in result["findings"]:
            for key in FINDING_KEYS:
                self.assertIn(key, f)
            self.assertFalse([k for k in f if k.startswith("_")], "private keys leaked: %r" % f)
            self.assertIn(f["severity"], SEVERITIES)
            self.assertIn(f["impact"], IMPACTS)
            self.assertIn(f["category"], CATEGORIES)
            self.assertRegex(f["id"], r"^[a-z0-9_]+$")
            for key in ("title", "what_it_means", "evidence"):
                self.assertIsInstance(f[key], str, key)
                self.assertTrue(f[key].strip(), "%s empty in %s" % (key, f["id"]))
            self.assertIsInstance(f["how_to_fix"], list)
            self.assertTrue(f["how_to_fix"], "how_to_fix empty in %s" % f["id"])
            for step in f["how_to_fix"]:
                self.assertIsInstance(step, str)
                self.assertTrue(step.strip())
        ids = [f["id"] for f in result["findings"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate finding ids: %r" % ids)
        for item in result["checklist"]:
            for key in CHECK_KEYS:
                self.assertIn(key, item)
                self.assertIsInstance(item[key], str)
                self.assertTrue(item[key].strip(), "%s empty in %s" % (key, item["id"]))
            self.assertIn(item["status"], ("pass", "fail", "unknown", "manual"))
        cov = result["data_coverage"]
        for key in ("deco", "link", "latency", "speed", "dns"):
            self.assertIsInstance(cov[key], bool)
        self.assertIsInstance(cov["rooms"], int)
        json.dumps(result)  # must be JSON-serialisable


# ---------------------------------------------------------------------------

class EmptyAndBrokenInput(AnalyzeTestCase):
    def test_empty_snapshot(self):
        r = analyze({})
        self.assertWellFormed(r)
        self.assertIsNone(r["score"])
        self.assertIsNone(r["grade"])
        self.assertEqual(r["bottleneck"], "not enough data")
        self.assertFinding(r, "need_deco_login", "low")
        self.assertFinding(r, "need_speed_test", "low")
        self.assertFinding(r, "need_quick_check", "low")
        self.assertFinding(r, "need_room_tests", "low")
        self.assertEqual(by_id(r)["need_deco_login"]["category"], "this computer")

    def test_all_none_snapshot(self):
        snap = {"generated_at": None, "demo": False, "settings": None, "deco": None, "deco_error": None,
                "link": None, "latency": None, "speed": None, "dns": None, "history": None}
        r = analyze(snap)
        self.assertWellFormed(r)
        self.assertIsNone(r["score"])
        self.assertEqual(r["data_coverage"]["rooms"], 0)

    def test_not_a_dict(self):
        for bad in (None, [], "x", 5):
            r = analyze(bad)
            self.assertWellFormed(r)
            self.assertIsNone(r["score"])

    def test_inner_values_none(self):
        snap = perfect_snapshot()
        snap["deco"] = {"nodes": None, "clients": None, "wifi": None, "wan": None, "performance": None}
        snap["link"] = {k: None for k in snap["link"]}
        snap["latency"] = {"gateway": None, "internet": None}
        snap["speed"] = {k: None for k in snap["speed"]}
        snap["dns"] = {"median_ms": None}
        snap["history"] = [None, 3, {"room": None}]
        r = analyze(snap)
        self.assertWellFormed(r)
        self.assertIsNotNone(r["score"])  # deco is a dict, so we have *some* data

    def test_garbage_values(self):
        snap = perfect_snapshot()
        node = snap["deco"]["nodes"][1]
        node["signal_dbm"] = "bad"
        node["backhaul"] = "wireless"
        node["backhaul_bands"] = "band5"
        node["rx_rate_mbps"] = [1, 2]
        node["client_count"] = "many"
        snap["deco"]["nodes"].append("not a node")
        snap["deco"]["clients"].append(None)
        snap["deco"]["wifi"]["bands"]["band5"] = "on"
        snap["deco"]["performance"] = {"cpu_pct": "high", "mem_pct": float("nan")}
        snap["link"]["rssi_dbm"] = "strong"
        snap["latency"]["internet"] = [None, {"loss_pct": "x"}]
        snap["speed"]["down_mbps"] = "fast"
        snap["settings"]["plan_down_mbps"] = -5
        r = analyze(snap)
        self.assertWellFormed(r)
        self.assertEqual(r["rule_errors"], [])

    def test_a_crashing_rule_does_not_break_the_rest(self):
        def boom(ctx):
            raise RuntimeError("bad rule")

        analyze_mod.RULES.insert(0, boom)
        try:
            r = analyze(perfect_snapshot())
        finally:
            analyze_mod.RULES.remove(boom)
        self.assertWellFormed(r)
        self.assertTrue(any("boom" in e for e in r["rule_errors"]))
        self.assertFinding(r, "plan_is_ceiling", "good")


class PerfectNetwork(AnalyzeTestCase):
    def test_perfect_network(self):
        r = analyze(perfect_snapshot())
        self.assertWellFormed(r)
        self.assertGreaterEqual(r["score"], 90)
        self.assertEqual(r["grade"], "A")
        bad = [f["id"] for f in r["findings"] if f["severity"] in ("critical", "high")]
        self.assertEqual(bad, [])
        self.assertEqual(r["bottleneck"], "internet plan")
        self.assertIn("plan", r["headline"])
        for fid in ("plan_is_ceiling", "all_decos_online", "ethernet_backhaul_all", "computer_signal_strong",
                    "bufferbloat_ok", "dns_ok", "gateway_latency_ok", "no_double_nat", "mlo_on",
                    "channel_widths_ok", "rooms_even", "ipv6_on", "network_names_ok"):
            self.assertFinding(r, fid, "good")
        self.assertEqual(r["data_coverage"],
                         {"deco": True, "link": True, "latency": True, "speed": True, "dns": True, "rooms": 2})

    def test_perfect_checklist(self):
        r = analyze(perfect_snapshot())
        items = {c["id"]: c for c in r["checklist"]}
        expected = ("ethernet_backhaul", "strong_satellite_signal", "six_ghz_on", "mlo_on", "one_network_name",
                    "no_hidden_network", "fast_roaming", "beamforming", "iot_network", "qos_for_bufferbloat",
                    "firmware", "no_double_nat", "ipv6", "dns_fast", "multi_gig_port", "main_deco_placement")
        for cid in expected:
            self.assertIn(cid, items)
        self.assertEqual(len(items), len(r["checklist"]), "duplicate checklist ids")
        for cid in ("ethernet_backhaul", "strong_satellite_signal", "six_ghz_on", "mlo_on", "one_network_name",
                    "no_hidden_network", "iot_network", "qos_for_bufferbloat", "no_double_nat", "ipv6",
                    "dns_fast", "multi_gig_port"):
            self.assertEqual(items[cid]["status"], "pass", cid)
        for cid in ("fast_roaming", "beamforming", "firmware", "main_deco_placement"):
            self.assertEqual(items[cid]["status"], "manual", cid)
        self.assertIn("Fast Roaming", items["fast_roaming"]["how"])

    def test_empty_checklist_is_unknown_or_manual(self):
        r = analyze({})
        for item in r["checklist"]:
            self.assertIn(item["status"], ("unknown", "manual"), item["id"])


class MeshRules(AnalyzeTestCase):
    def test_unit_offline(self):
        snap = perfect_snapshot()
        snap["deco"]["nodes"][2]["online"] = False
        r = analyze(snap)
        f = self.assertFinding(r, "deco_offline", "critical")
        self.assertIn("Office", f["title"])
        self.assertEqual(r["findings"][0]["id"], "deco_offline")
        self.assertIn("down", r["headline"])

    def test_internet_offline_on_main(self):
        snap = perfect_snapshot()
        snap["deco"]["nodes"][0]["internet_online"] = False
        r = analyze(snap)
        f = self.assertFinding(r, "deco_internet_offline", "critical")
        self.assertIn("main Deco", f["title"])

    def test_internet_offline_on_satellite(self):
        snap = perfect_snapshot()
        snap["deco"]["nodes"][1]["internet_online"] = False
        r = analyze(snap)
        f = self.assertFinding(r, "deco_internet_offline", "critical")
        self.assertIn("Kids", f["title"])

    def test_weak_backhaul_high(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -75, "band2_4": -60}, bands=("band2_4", "band5"))
        r = analyze(snap)
        f = self.assertFinding(r, "satellite_wireless_backhaul_weak", "high")
        self.assertIn("Kids", f["title"])
        self.assertIn("-75", f["evidence"])
        self.assertIn("backhaul", f["what_it_means"].lower())
        self.assertEqual(r["bottleneck"], "mesh backhaul")

    def test_weak_backhaul_medium(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -68})
        r = analyze(snap)
        self.assertFinding(r, "satellite_wireless_backhaul_weak", "medium")

    def test_backhaul_uses_best_high_band(self):
        snap = wireless_sat(perfect_snapshot(), bands=("band5", "band6"), dbm={"band5": -74, "band6": -60})
        r = analyze(snap)
        self.assertNoFinding(r, "satellite_wireless_backhaul_weak")
        self.assertFinding(r, "satellite_backhaul_strong", "good")

    def test_strong_backhaul_is_fine(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -55})
        r = analyze(snap)
        self.assertNoFinding(r, "satellite_wireless_backhaul_weak")
        self.assertFinding(r, "satellite_backhaul_strong", "good")

    def test_weak_backhaul_bars_only(self):
        snap = wireless_sat(perfect_snapshot(), bands=("band2_4", "band5"), bars={"band5": 2, "band2_4": 3})
        r = analyze(snap)
        f = self.assertFinding(r, "satellite_wireless_backhaul_weak", "high")
        self.assertIn("2 bars", f["evidence"])

    def test_good_bars_are_fine(self):
        snap = wireless_sat(perfect_snapshot(), bars={"band5": 4})
        r = analyze(snap)
        self.assertNoFinding(r, "satellite_wireless_backhaul_weak")

    def test_backhaul_only_2g(self):
        snap = wireless_sat(perfect_snapshot(), bands=("band2_4",), dbm={"band2_4": -60})
        r = analyze(snap)
        self.assertFinding(r, "satellite_backhaul_2g_only", "high")

    def test_backhaul_only_2g_from_signal(self):
        snap = wireless_sat(perfect_snapshot(), bands=(), dbm={"band2_4": -60})
        r = analyze(snap)
        self.assertFinding(r, "satellite_backhaul_2g_only", "high")

    def test_wireless_backhaul_recommends_ethernet(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -55}, rx={"band5": 1800}, tx={"band5": 1700})
        r = analyze(snap)
        f = self.assertFinding(r, "use_ethernet_backhaul", "low")
        self.assertEqual(f["impact"], "big")
        steps = " ".join(f["how_to_fix"])
        self.assertIn("2.5 Gbps", steps)
        self.assertIn("Cat6", steps)
        self.assertIn("switch", steps)
        self.assertIn("by itself", steps)
        self.assertNoFinding(r, "ethernet_backhaul_all")

    def test_ethernet_tip_is_medium_when_link_is_weak(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -72})
        r = analyze(snap)
        self.assertFinding(r, "use_ethernet_backhaul", "medium")

    def test_ethernet_tip_without_multigig_model(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -55})
        for n in snap["deco"]["nodes"]:
            n["model"] = "X50"
        r = analyze(snap)
        f = self.assertFinding(r, "use_ethernet_backhaul")
        self.assertNotIn("2.5 Gbps", " ".join(f["how_to_fix"][:2]))

    def test_daisy_chain(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -55})
        snap = wireless_sat(snap, name="Office", mac=OFFICE_MAC, parent=KIDS_MAC, dbm={"band5": -58})
        r = analyze(snap)
        f = self.assertFinding(r, "satellite_daisy_chain", "medium")
        self.assertIn("Office", f["title"])
        self.assertIn("Kids", f["title"])
        self.assertIn("halves", f["what_it_means"])

    def test_no_daisy_chain_when_wired(self):
        snap = perfect_snapshot()
        snap["deco"]["nodes"][2]["parent_mac"] = KIDS_MAC
        r = analyze(snap)
        self.assertNoFinding(r, "satellite_daisy_chain")

    def test_slow_backhaul_link_rate(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -60}, rx={"band5": 300, "band2_4": 500},
                            tx={"band5": 250})
        r = analyze(snap)
        f = self.assertFinding(r, "satellite_backhaul_slow_link", "medium")
        self.assertIn("300", f["evidence"])

    def test_fast_backhaul_link_rate(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -60}, rx={"band5": 960}, tx={"band5": 1297})
        r = analyze(snap)
        self.assertNoFinding(r, "satellite_backhaul_slow_link")

    def test_firmware_mismatch(self):
        snap = perfect_snapshot()
        snap["deco"]["nodes"][1]["fw_version"] = "1.0.9 Build 20240101 Rel. 900"
        r = analyze(snap)
        f = self.assertFinding(r, "firmware_mismatch", "low")
        self.assertIn("1.0.9", f["evidence"])
        items = {c["id"]: c for c in r["checklist"]}
        self.assertEqual(items["firmware"]["status"], "fail")

    def test_firmware_different_models_is_ok(self):
        snap = perfect_snapshot()
        snap["deco"]["nodes"][1]["fw_version"] = "1.0.9 Build 20240101 Rel. 900"
        snap["deco"]["nodes"][1]["model"] = "BE25"
        r = analyze(snap)
        self.assertNoFinding(r, "firmware_mismatch")

    def test_main_busy_cpu(self):
        snap = perfect_snapshot()
        snap["deco"]["performance"] = {"cpu_pct": 91.0, "mem_pct": 50.0}
        r = analyze(snap)
        f = self.assertFinding(r, "main_deco_busy", "medium")
        self.assertIn("91%", f["evidence"])

    def test_main_busy_memory(self):
        snap = perfect_snapshot()
        snap["deco"]["performance"] = {"cpu_pct": 20.0, "mem_pct": 95.0}
        self.assertFinding(analyze(snap), "main_deco_busy", "medium")

    def test_client_imbalance(self):
        snap = perfect_snapshot()
        counts = (14, 3, 1)
        for n, c in zip(snap["deco"]["nodes"], counts):
            n["client_count"] = c
        r = analyze(snap)
        f = self.assertFinding(r, "client_load_unbalanced", "low")
        self.assertIn("Living Room", f["title"])

    def test_client_balance_needs_enough_devices(self):
        snap = perfect_snapshot()
        for n, c in zip(snap["deco"]["nodes"], (5, 1, 0)):
            n["client_count"] = c
        self.assertNoFinding(analyze(snap), "client_load_unbalanced")


class WifiSettingRules(AnalyzeTestCase):
    def test_many_clients_on_2g(self):
        snap = perfect_snapshot()
        snap["deco"]["clients"] = [_client(i, "band2_4") for i in range(6)] + [_client(i, "band5") for i in range(6, 10)]
        snap["deco"]["wifi"]["iot_enabled"] = False
        r = analyze(snap)
        f = self.assertFinding(r, "many_clients_on_2g", "low")
        self.assertIn("6 of 10", f["evidence"])
        self.assertIn("IoT", " ".join(f["how_to_fix"]))
        self.assertIn("smart", f["what_it_means"].lower())
        items = {c["id"]: c for c in r["checklist"]}
        self.assertEqual(items["iot_network"]["status"], "fail")

    def test_few_clients_on_2g_is_fine(self):
        self.assertNoFinding(analyze(perfect_snapshot()), "many_clients_on_2g")

    def test_6ghz_off(self):
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["bands"]["band6"]["enabled"] = False
        r = analyze(snap)
        self.assertFinding(r, "band_6ghz_off", "medium")
        self.assertEqual({c["id"]: c for c in r["checklist"]}["six_ghz_on"]["status"], "fail")

    def test_5ghz_off(self):
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["bands"]["band5"]["enabled"] = False
        self.assertFinding(analyze(snap), "band_5ghz_off", "high")

    def test_6ghz_checklist_passes_on_dual_band_model(self):
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["bands"]["band6"] = None
        for n in snap["deco"]["nodes"]:
            n["model"] = "BE25"
        r = analyze(snap)
        self.assertEqual({c["id"]: c for c in r["checklist"]}["six_ghz_on"]["status"], "pass")
        self.assertNoFinding(r, "band_6ghz_off")

    def test_narrow_5ghz(self):
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["bands"]["band5"]["width_mhz"] = 40
        r = analyze(snap)
        f = self.assertFinding(r, "narrow_5ghz_channel", "medium")
        self.assertIn("40", f["evidence"])

    def test_narrow_6ghz(self):
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["bands"]["band6"]["width_mhz"] = 80
        self.assertFinding(analyze(snap), "narrow_6ghz_channel", "low")

    def test_2g_at_40mhz(self):
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["bands"]["band2_4"]["width_mhz"] = 40
        f = self.assertFinding(analyze(snap), "wide_2g_channel", "low")
        self.assertIn("20 MHz", f["what_it_means"])

    def test_mlo_off(self):
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["mlo_enabled"] = False
        r = analyze(snap)
        f = self.assertFinding(r, "mlo_off", "low")
        self.assertIn("two bands at once", f["what_it_means"])
        self.assertEqual({c["id"]: c for c in r["checklist"]}["mlo_on"]["status"], "fail")

    def test_mlo_unknown_is_silent(self):
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["mlo_enabled"] = None
        r = analyze(snap)
        self.assertNoFinding(r, "mlo_off")
        self.assertNoFinding(r, "mlo_on")

    def test_hidden_network(self):
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["bands"]["band5"]["hidden"] = True
        r = analyze(snap)
        self.assertFinding(r, "hidden_network", "low")
        self.assertEqual({c["id"]: c for c in r["checklist"]}["no_hidden_network"]["status"], "fail")

    def test_split_names(self):
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["same_ssid_all_bands"] = False
        r = analyze(snap)
        self.assertFinding(r, "split_network_names", "low")
        self.assertEqual({c["id"]: c for c in r["checklist"]}["one_network_name"]["status"], "fail")


class InternetRules(AnalyzeTestCase):
    def test_double_nat(self):
        snap = perfect_snapshot()
        snap["deco"]["wan"].update({"wan_ip": "192.168.1.11", "gateway": "192.168.1.1", "double_nat": True})
        r = analyze(snap)
        f = self.assertFinding(r, "double_nat", "medium")
        steps = " ".join(f["how_to_fix"])
        self.assertIn("bridge", steps)
        self.assertIn("Access Point", steps)
        self.assertIn("192.168.1.11", f["evidence"])
        self.assertNoFinding(r, "no_double_nat")

    def test_cgnat(self):
        snap = perfect_snapshot()
        snap["deco"]["wan"].update({"wan_ip": "100.70.1.2", "double_nat": False, "cgnat": True})
        r = analyze(snap)
        self.assertFinding(r, "cgnat", "low")
        self.assertNoFinding(r, "no_double_nat")

    def test_ipv6_off(self):
        snap = perfect_snapshot()
        snap["deco"]["wan"]["ipv6_enabled"] = False
        self.assertFinding(analyze(snap), "ipv6_off", "low")

    def test_speed_below_half_plan(self):
        snap = perfect_snapshot()
        snap["speed"]["down_mbps"] = 180.0
        snap["link"]["tx_rate_mbps"] = 600.0
        snap["link"]["rx_rate_mbps"] = 600.0
        r = analyze(snap)
        f = self.assertFinding(r, "speed_below_plan", "high")
        self.assertIn("36%", f["evidence"])

    def test_speed_below_80_percent(self):
        snap = perfect_snapshot()
        snap["speed"]["down_mbps"] = 350.0
        snap["link"]["tx_rate_mbps"] = 700.0
        snap["link"]["rx_rate_mbps"] = 700.0
        snap["link"]["rssi_dbm"] = -70
        self.assertFinding(analyze(snap), "speed_below_plan", "medium")

    def test_speed_low_blames_provider(self):
        snap = perfect_snapshot()
        snap["speed"]["down_mbps"] = 200.0
        r = analyze(snap)
        f = self.assertFinding(r, "speed_below_plan_provider", "high")
        self.assertNoFinding(r, "speed_below_plan")
        self.assertIn("cable", " ".join(f["how_to_fix"]))
        self.assertEqual(r["bottleneck"], "internet plan")

    def test_speed_low_not_provider_when_gateway_slow(self):
        snap = perfect_snapshot()
        snap["speed"]["down_mbps"] = 200.0
        snap["latency"]["gateway"]["median_ms"] = 25.0
        r = analyze(snap)
        self.assertFinding(r, "speed_below_plan", "high")
        self.assertNoFinding(r, "speed_below_plan_provider")

    def test_plan_is_ceiling(self):
        r = analyze(perfect_snapshot())
        self.assertFinding(r, "plan_is_ceiling", "good")

    def test_speed_close_to_plan(self):
        snap = perfect_snapshot()
        snap["speed"]["down_mbps"] = 425.0
        r = analyze(snap)
        self.assertFinding(r, "speed_close_to_plan", "good")
        self.assertNoFinding(r, "speed_below_plan")
        self.assertEqual(r["bottleneck"], "internet plan")

    def test_no_plan_means_none_found(self):
        snap = perfect_snapshot()
        snap["settings"]["plan_down_mbps"] = None
        snap["settings"]["plan_up_mbps"] = None
        r = analyze(snap)
        self.assertEqual(r["bottleneck"], "none found")
        self.assertFinding(r, "need_plan_speed", "low")
        self.assertEqual(r["score"], 100)
        self.assertIn("nothing", r["headline"].lower())

    def test_internet_offline_main_comes_first(self):
        snap = perfect_snapshot()
        snap["deco"]["nodes"][0]["internet_online"] = False
        snap["deco"]["nodes"][2]["online"] = False
        r = analyze(snap)
        self.assertEqual(r["findings"][0]["id"], "deco_internet_offline")
        self.assertIn("modem", r["headline"])

    def test_internet_loss_blames_wifi_when_local_loss_too(self):
        snap = perfect_snapshot()
        snap["latency"]["gateway"]["loss_pct"] = 5.0
        for t in snap["latency"]["internet"]:
            t["loss_pct"] = 5.0
        r = analyze(snap)
        f = self.assertFinding(r, "internet_packet_loss", "high")
        self.assertIn("Wi-Fi first", f["how_to_fix"][0])
        self.assertEqual(r["bottleneck"], "wifi signal")

    def test_upload_below_plan(self):
        snap = perfect_snapshot()
        snap["speed"]["up_mbps"] = 10.0
        self.assertFinding(analyze(snap), "upload_below_plan", "medium")

    def test_bufferbloat_c(self):
        snap = perfect_snapshot()
        snap["speed"].update({"bufferbloat_grade": "C", "bufferbloat_ms": 120.0, "loaded_latency_down_ms": 132.0})
        r = analyze(snap)
        f = self.assertFinding(r, "bufferbloat", "medium")
        steps = " ".join(f["how_to_fix"])
        self.assertIn("QoS", steps)
        self.assertIn("432 Mbps", steps)  # 90% of 480
        self.assertEqual(r["bottleneck"], "bufferbloat")
        self.assertEqual({c["id"]: c for c in r["checklist"]}["qos_for_bufferbloat"]["status"], "fail")

    def test_bufferbloat_d_and_f(self):
        for grade in ("D", "F"):
            snap = perfect_snapshot()
            snap["speed"]["bufferbloat_grade"] = grade
            self.assertFinding(analyze(snap), "bufferbloat", "high")

    def test_gateway_latency_medium(self):
        snap = perfect_snapshot()
        snap["latency"]["gateway"].update({"median_ms": 18.0, "jitter_ms": 4.0})
        r = analyze(snap)
        f = self.assertFinding(r, "local_connection_unsteady", "medium")
        self.assertIn("18", f["evidence"])

    def test_gateway_jitter_and_loss(self):
        snap = perfect_snapshot()
        snap["latency"]["gateway"].update({"jitter_ms": 12.0})
        self.assertFinding(analyze(snap), "local_connection_unsteady", "medium")
        snap["latency"]["gateway"].update({"loss_pct": 8.0})
        self.assertFinding(analyze(snap), "local_connection_unsteady", "high")

    def test_internet_loss(self):
        snap = perfect_snapshot()
        for t in snap["latency"]["internet"]:
            t["loss_pct"] = 6.7
        r = analyze(snap)
        self.assertFinding(r, "internet_packet_loss", "high")

    def test_internet_loss_one_server_only_is_ignored(self):
        snap = perfect_snapshot()
        snap["latency"]["internet"][0]["loss_pct"] = 6.7
        self.assertNoFinding(analyze(snap), "internet_packet_loss")

    def test_dns_slow(self):
        snap = perfect_snapshot()
        snap["deco"]["wan"]["dns"] = ["192.168.1.1"]   # not a fast public resolver yet
        snap["dns"]["median_ms"] = 140.0
        r = analyze(snap)
        f = self.assertFinding(r, "dns_slow", "medium")
        self.assertIn("1.1.1.1", " ".join(f["how_to_fix"]))
        self.assertIn(knowledge.APP_PATHS["dns"], f["how_to_fix"][0])
        self.assertEqual(r["bottleneck"], "dns")
        self.assertEqual({c["id"]: c for c in r["checklist"]}["dns_fast"]["status"], "fail")


class ThisComputerRules(AnalyzeTestCase):
    def test_ethernet(self):
        snap = perfect_snapshot()
        snap["link"] = {"os": "linux", "type": "ethernet", "interface": "eth0"}
        self.assertFinding(analyze(snap), "computer_on_ethernet", "good")

    def test_weak_rssi_high(self):
        snap = perfect_snapshot()
        snap["link"]["rssi_dbm"] = -80
        r = analyze(snap)
        f = self.assertFinding(r, "computer_weak_signal", "high")
        self.assertIn("-80", f["evidence"])
        self.assertIn("dBm", f["what_it_means"])

    def test_weak_rssi_medium(self):
        snap = perfect_snapshot()
        snap["link"]["rssi_dbm"] = -70
        self.assertFinding(analyze(snap), "computer_weak_signal", "medium")

    def test_rssi_okay(self):
        snap = perfect_snapshot()
        snap["link"]["rssi_dbm"] = -62
        self.assertNoFinding(analyze(snap), "computer_weak_signal")

    def test_low_snr(self):
        snap = perfect_snapshot()
        snap["link"]["snr_db"] = 15
        self.assertFinding(analyze(snap), "computer_low_snr", "medium")

    def test_on_2g(self):
        snap = perfect_snapshot()
        snap["link"]["band"] = "2.4GHz"
        self.assertFinding(analyze(snap), "computer_on_2g", "medium")

    def test_old_phy(self):
        snap = perfect_snapshot()
        snap["link"].update({"phy": "802.11ac", "wifi_gen": 5, "band": "5GHz"})
        r = analyze(snap)
        f = self.assertFinding(r, "computer_old_wifi", "low")
        self.assertIn("limit", f["what_it_means"])

    def test_old_phy_from_phy_string(self):
        snap = perfect_snapshot()
        snap["link"].update({"phy": "802.11n", "wifi_gen": None})
        self.assertFinding(analyze(snap), "computer_old_wifi", "low")

    def test_low_tx_rate(self):
        snap = perfect_snapshot()
        snap["link"].update({"tx_rate_mbps": 144.0, "rx_rate_mbps": 130.0})
        snap["speed"]["down_mbps"] = 90.0   # what a 144 Mbps link can really carry
        r = analyze(snap)
        f = self.assertFinding(r, "computer_low_link_rate", "medium")
        self.assertIn("144", f["evidence"])

    def test_link_slower_than_plan(self):
        snap = perfect_snapshot()
        snap["settings"]["plan_down_mbps"] = 1000.0
        snap["link"].update({"tx_rate_mbps": 1201.0, "rx_rate_mbps": 1100.0})
        self.assertFinding(analyze(snap), "computer_link_below_plan", "low")

    def test_link_type_guessed_from_rssi(self):
        snap = perfect_snapshot()
        snap["link"]["type"] = "unknown"
        snap["link"]["rssi_dbm"] = -80
        r = analyze(snap)
        self.assertTrue(r["data_coverage"]["link"])
        self.assertFinding(r, "computer_weak_signal", "high")

    def test_link_error_only_is_not_coverage(self):
        snap = perfect_snapshot()
        snap["link"] = {"os": "linux", "type": "unknown", "error": "no wifi tool"}
        r = analyze(snap)
        self.assertFalse(r["data_coverage"]["link"])
        self.assertFinding(r, "need_quick_check")


class RoomRules(AnalyzeTestCase):
    def test_weak_room_by_speed(self):
        snap = perfect_snapshot()
        snap["history"].append({"room": "Garage", "at": "2026-11-25T20:10:00+00:00", "down_mbps": 120.0,
                                "rssi_dbm": -66, "node_name": "Office"})
        r = analyze(snap)
        f = self.assertFinding(r, "weak_room", "medium")
        self.assertIn("Garage", f["title"])
        self.assertIn("halfway", " ".join(f["how_to_fix"]))
        self.assertNoFinding(r, "rooms_even")

    def test_weak_room_by_signal(self):
        snap = perfect_snapshot()
        snap["history"].append({"room": "Attic", "at": "2026-11-25T20:10:00+00:00", "down_mbps": 400.0,
                                "rssi_dbm": -74})
        f = self.assertFinding(analyze(snap), "weak_room")
        self.assertIn("Attic", f["title"])

    def test_latest_test_per_room_counts(self):
        snap = perfect_snapshot()
        snap["history"].insert(0, {"room": "Bedroom", "down_mbps": 20.0, "rssi_dbm": -80})
        self.assertNoFinding(analyze(snap), "weak_room")

    def test_single_room_asks_for_more(self):
        snap = perfect_snapshot()
        snap["history"] = snap["history"][:1]
        r = analyze(snap)
        self.assertNoFinding(r, "weak_room")
        self.assertFinding(r, "need_room_tests", "low")


class MissingData(AnalyzeTestCase):
    def test_only_link_data(self):
        snap = {"settings": {}, "link": perfect_snapshot()["link"], "history": []}
        r = analyze(snap)
        self.assertWellFormed(r)
        self.assertIsNotNone(r["score"])
        self.assertFinding(r, "need_deco_login", "low")
        self.assertFinding(r, "need_speed_test", "low")
        self.assertFinding(r, "need_plan_speed", "low")
        self.assertEqual(r["bottleneck"], "not enough data")

    def test_missing_data_does_not_lower_score(self):
        snap = perfect_snapshot()
        snap["history"] = []
        r = analyze(snap)
        self.assertFinding(r, "need_room_tests", "low")
        self.assertEqual(r["score"], analyze(perfect_snapshot())["score"])

    def test_deco_error_in_evidence(self):
        snap = perfect_snapshot()
        snap["deco"] = None
        snap["deco_error"] = "Wrong password"
        f = self.assertFinding(analyze(snap), "need_deco_login")
        self.assertIn("Wrong password", f["evidence"])


class ScoringAndOrder(AnalyzeTestCase):
    def terrible_snapshot(self):
        snap = perfect_snapshot()
        snap["deco"]["nodes"][2]["online"] = False
        snap["deco"]["nodes"][0]["internet_online"] = False
        snap = wireless_sat(snap, dbm={"band5": -80}, rx={"band5": 100})
        snap["deco"]["wifi"]["bands"]["band5"]["enabled"] = False
        snap["deco"]["wifi"]["bands"]["band6"]["enabled"] = False
        snap["link"].update({"rssi_dbm": -82, "snr_db": 10, "band": "2.4GHz", "tx_rate_mbps": 50.0})
        snap["speed"].update({"down_mbps": 20.0, "bufferbloat_grade": "F"})
        snap["dns"]["median_ms"] = 300.0
        snap["deco"]["wan"]["double_nat"] = True
        return snap

    def test_score_clamped_low(self):
        r = analyze(self.terrible_snapshot())
        self.assertWellFormed(r)
        self.assertEqual(r["score"], 5)
        self.assertEqual(r["grade"], "F")

    def test_score_clamped_high(self):
        self.assertEqual(analyze(perfect_snapshot())["score"], 100)
        self.assertEqual(analyze_mod.score_findings([]), 100)
        self.assertEqual(analyze_mod.score_findings([{"severity": "critical"}] * 10), 5)

    def test_score_penalties(self):
        fs = [{"severity": "critical"}, {"severity": "high"}, {"severity": "medium"},
              {"severity": "low"}, {"severity": "good"}]
        self.assertEqual(analyze_mod.score_findings(fs), 100 - 30 - 15 - 7 - 2)

    def test_grades(self):
        g = analyze_mod.grade_for
        self.assertEqual([g(100), g(90), g(89), g(80), g(79), g(65), g(64), g(50), g(49), g(5)],
                         ["A", "A", "B", "B", "C", "C", "D", "D", "F", "F"])
        self.assertIsNone(g(None))

    def test_sorted_by_severity_then_impact(self):
        for snap in (self.terrible_snapshot(), perfect_snapshot(), {}):
            r = analyze(snap)
            keys = [(SEVERITIES.index(f["severity"]), IMPACTS.index(f["impact"])) for f in r["findings"]]
            self.assertEqual(keys, sorted(keys))

    def test_headline_names_bottleneck(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -78})
        snap["speed"]["down_mbps"] = 150.0
        r = analyze(snap)
        self.assertEqual(r["bottleneck"], "mesh backhaul")
        self.assertIn("backhaul", r["headline"])
        self.assertIn("Kids", r["headline"])

    def test_device_bottleneck(self):
        snap = perfect_snapshot()
        snap["link"].update({"phy": "802.11ac", "wifi_gen": 5, "band": "5GHz", "tx_rate_mbps": 866.0,
                             "rx_rate_mbps": 866.0})
        snap["speed"]["down_mbps"] = 300.0
        snap["settings"]["plan_down_mbps"] = 1000.0
        r = analyze(snap)
        self.assertFinding(r, "speed_below_plan", "high")
        self.assertIn(r["bottleneck"], ("device", "wifi signal"))


class Readability(AnalyzeTestCase):
    @staticmethod
    def words_per_sentence(text):
        sentences = [s for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s.strip()]
        words = len(text.split())
        return words / float(max(1, len(sentences)))

    def all_findings(self):
        snaps = [perfect_snapshot(), ScoringAndOrder().terrible_snapshot(), {}]
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -68})
        snap = wireless_sat(snap, name="Office", mac=OFFICE_MAC, parent=KIDS_MAC, bands=("band2_4",),
                            dbm={"band2_4": -60})
        snap["deco"]["clients"] = [_client(i, "band2_4") for i in range(8)]
        for n, c in zip(snap["deco"]["nodes"], (20, 2, 1)):
            n["client_count"] = c
        snap["deco"]["nodes"][1]["fw_version"] = "0.9"
        snap["deco"]["performance"]["cpu_pct"] = 95.0
        snap["deco"]["wifi"].update({"mlo_enabled": False, "same_ssid_all_bands": False, "iot_enabled": False})
        snap["deco"]["wifi"]["bands"]["band5"]["width_mhz"] = 40
        snap["deco"]["wifi"]["bands"]["band6"]["width_mhz"] = 80
        snap["deco"]["wifi"]["bands"]["band2_4"].update({"width_mhz": 40, "hidden": True})
        snap["deco"]["wan"].update({"cgnat": True, "ipv6_enabled": False})
        snap["link"].update({"phy": "802.11ac", "wifi_gen": 5, "rssi_dbm": -70})
        snap["latency"]["gateway"]["median_ms"] = 15.0
        snap["speed"]["bufferbloat_grade"] = "C"
        snap["speed"]["up_mbps"] = 5.0
        snap["history"].append({"room": "Garage", "down_mbps": 50.0, "rssi_dbm": -78})
        snaps.append(snap)
        out = []
        for s in snaps:
            out.extend(analyze(s)["findings"])
        return out

    def test_coverage_of_texts(self):
        ids = set(f["id"] for f in self.all_findings())
        self.assertGreaterEqual(len(ids), 35)

    def test_sentences_are_short(self):
        findings = self.all_findings()
        total_words = 0
        total_sentences = 0
        for f in findings:
            text = f["what_it_means"]
            self.assertLessEqual(self.words_per_sentence(text), 22, "%s: %s" % (f["id"], text))
            sentences = [s for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s.strip()]
            self.assertLessEqual(len(sentences), 4, f["id"])
            total_words += len(text.split())
            total_sentences += len(sentences)
        self.assertLessEqual(total_words / float(total_sentences), 22)

    def test_no_shouting(self):
        for f in self.all_findings():
            for text in [f["title"], f["what_it_means"]] + f["how_to_fix"]:
                self.assertNotIn("!!", text)
                caps = re.findall(r"\b[A-Z]{6,}\b", text)
                self.assertEqual(caps, [], "%s: %s" % (f["id"], text))

    def test_all_well_formed(self):
        snaps = [perfect_snapshot(), ScoringAndOrder().terrible_snapshot(), {}]
        for s in snaps:
            self.assertWellFormed(analyze(s))


class Knowledge(unittest.TestCase):
    def test_be65(self):
        info = knowledge.model_info("BE65")
        self.assertEqual(info["code"], "BE65")
        self.assertEqual(info["marketing_class"], "BE11000")
        self.assertEqual(info["wifi_gen"], 7)
        self.assertEqual(info["max_port_gbps"], 2.5)
        self.assertTrue(info["supports_320mhz"])
        self.assertTrue(info["supports_mlo"])
        self.assertIn("band6", info["bands"])
        self.assertTrue(info["sources"])

    def test_model_spellings(self):
        for text in ("Deco BE65", "be65", "BE65(US)", "BE65 v2", "Deco BE65 V1.0", "BE65 3-pack"):
            info = knowledge.model_info(text)
            self.assertIsNotNone(info, text)
            self.assertEqual(info["code"], "BE65", text)
        self.assertEqual(knowledge.model_info("Deco BE65 Pro")["code"], "BE65 PRO")
        self.assertEqual(knowledge.model_info("x50")["code"], "X50")

    def test_unknown_models(self):
        for text in (None, "", "BE65-5G", "M5", 65, ["BE65"]):
            self.assertIsNone(knowledge.model_info(text), text)

    def test_model_info_returns_copy(self):
        info = knowledge.model_info("BE65")
        info["bands"].append("band9")
        self.assertNotIn("band9", knowledge.MODELS["BE65"]["bands"])

    def test_models_shape(self):
        for code, spec in knowledge.MODELS.items():
            self.assertEqual(code, code.upper())
            for key in ("name", "wifi_gen", "bands", "max_port_gbps", "supports_320mhz", "supports_mlo",
                        "ports", "sources"):
                self.assertIn(key, spec, code)
            for band in spec["bands"]:
                self.assertIn(band, BANDS)
        self.assertEqual(sorted(knowledge.MARKETING_CLASSES["BE11000"]), ["BE65", "BE65 PRO"])

    def test_app_paths(self):
        for key in ("fast_roaming", "beamforming", "mlo", "iot_network", "qos", "ipv6", "dns",
                    "operation_mode", "firmware", "wifi_settings", "wifi_bands", "hide_network",
                    "channel_width", "six_ghz", "network_map"):
            self.assertIn(key, knowledge.APP_PATHS)
            self.assertTrue(knowledge.APP_PATHS[key].startswith("Deco app → "), key)
        self.assertIn("differ", knowledge.APP_PATHS_NOTE)

    def test_findings_add_app_version_note(self):
        snap = perfect_snapshot()
        snap["deco"]["wan"]["dns"] = ["192.168.1.1"]
        snap["dns"]["median_ms"] = 200.0
        f = by_id(analyze(snap))["dns_slow"]
        self.assertEqual(f["how_to_fix"][-1], knowledge.APP_PATHS_NOTE)


class AdversarialReview(AnalyzeTestCase):
    """Edge cases found in review: contradictions, misleading advice, odd input."""

    def test_daisy_chain_through_wired_satellite_is_not_flagged(self):
        # Kids is wired to the main Deco; Office links to Kids over Wi-Fi.
        # That is ONE wireless hop, which is fine (often the best choice).
        snap = wireless_sat(perfect_snapshot(), name="Office", mac=OFFICE_MAC, parent=KIDS_MAC,
                            dbm={"band5": -55})
        r = analyze(snap)
        self.assertWellFormed(r)
        self.assertNoFinding(r, "satellite_daisy_chain")

    def test_daisy_chain_through_wireless_satellite_still_flagged(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -55})
        snap = wireless_sat(snap, name="Office", mac=OFFICE_MAC, parent=KIDS_MAC, dbm={"band5": -55})
        self.assertFinding(analyze(snap), "satellite_daisy_chain", "medium")

    def test_offline_deco_is_not_blamed_for_client_imbalance(self):
        snap = perfect_snapshot()
        nodes = snap["deco"]["nodes"]
        nodes[2]["online"] = False
        for n, c in zip(nodes, (8, 2, 0)):
            n["client_count"] = c
        r = analyze(snap)
        self.assertFinding(r, "deco_offline", "critical")
        self.assertNoFinding(r, "client_load_unbalanced")

    def test_link_below_plan_not_shown_when_plan_is_reached(self):
        snap = perfect_snapshot()
        snap["link"].update({"tx_rate_mbps": 600.0, "rx_rate_mbps": 600.0})
        r = analyze(snap)
        self.assertFinding(r, "plan_is_ceiling", "good")
        self.assertNoFinding(r, "computer_link_below_plan")

    def test_low_link_rate_is_mild_when_plan_is_reached(self):
        snap = perfect_snapshot()
        snap["settings"]["plan_down_mbps"] = 100.0
        snap["speed"]["down_mbps"] = 95.0
        snap["link"].update({"tx_rate_mbps": 150.0, "rx_rate_mbps": 150.0})
        r = analyze(snap)
        self.assertFinding(r, "plan_is_ceiling", "good")
        f = self.assertFinding(r, "computer_low_link_rate", "low")
        self.assertNotIn("aren't possible", f["what_it_means"])

    def test_bufferbloat_target_without_upload_number(self):
        snap = perfect_snapshot()
        snap["speed"].update({"up_mbps": None, "bufferbloat_grade": "D"})
        f = self.assertFinding(analyze(snap), "bufferbloat", "high")
        joined = " ".join(f["how_to_fix"])
        self.assertNotIn("?", joined)
        self.assertIn("432 Mbps", joined)

    def test_bufferbloat_text_matches_what_deco_qos_does(self):
        # TP-Link FAQ 1601: Deco QoS puts chosen activities/devices first after
        # you enter the Total Bandwidth. It is not promised to "fix" lag.
        snap = perfect_snapshot()
        snap["speed"]["bufferbloat_grade"] = "C"
        f = self.assertFinding(analyze(snap), "bufferbloat", "medium")
        self.assertNotIn("can fix it", f["what_it_means"])
        self.assertIn("first", f["what_it_means"])
        self.assertTrue(any("Total Bandwidth" in s for s in f["how_to_fix"]))

    def test_gateway_lag_on_ethernet_does_not_blame_wifi(self):
        snap = perfect_snapshot()
        snap["link"] = {k: None for k in snap["link"]}
        snap["link"].update({"os": "linux", "type": "ethernet", "interface": "eth0"})
        snap["latency"]["gateway"].update({"median_ms": 20.0})
        r = analyze(snap)
        f = self.assertFinding(r, "local_connection_unsteady", "medium")
        text = " ".join([f["what_it_means"]] + f["how_to_fix"])
        self.assertNotIn("5 or 6 GHz", text)
        self.assertNotIn("Wi-Fi trouble", text)
        self.assertNotEqual(r["bottleneck"], "wifi signal")

    def test_internet_loss_on_ethernet_does_not_say_fix_wifi(self):
        snap = perfect_snapshot()
        snap["link"] = {k: None for k in snap["link"]}
        snap["link"].update({"os": "linux", "type": "ethernet", "interface": "eth0"})
        snap["latency"]["gateway"]["loss_pct"] = 4.0
        for t in snap["latency"]["internet"]:
            t["loss_pct"] = 5.0
        r = analyze(snap)
        f = self.assertFinding(r, "internet_packet_loss", "high")
        self.assertNotIn("Wi-Fi", " ".join(f["how_to_fix"]))
        self.assertNotEqual(r["bottleneck"], "wifi signal")

    def test_provider_not_blamed_when_computer_is_on_2g(self):
        # A 2.4 GHz link can be 2x a small plan, but it is still the weak spot.
        snap = perfect_snapshot()
        snap["settings"]["plan_down_mbps"] = 100.0
        snap["speed"]["down_mbps"] = 40.0
        snap["link"].update({"band": "2.4GHz", "channel": 6, "width_mhz": 40, "rssi_dbm": -55,
                             "tx_rate_mbps": 286.0, "rx_rate_mbps": 286.0})
        r = analyze(snap)
        self.assertFinding(r, "computer_on_2g", "medium")
        self.assertNoFinding(r, "speed_below_plan_provider")
        self.assertFinding(r, "speed_below_plan", "high")
        self.assertEqual(r["bottleneck"], "wifi signal")

    def test_provider_not_blamed_when_snr_or_jitter_is_bad(self):
        for tweak in ({"link": {"snr_db": 15}}, {"gateway": {"jitter_ms": 25.0}}):
            snap = perfect_snapshot()
            snap["speed"]["down_mbps"] = 150.0
            snap["link"].update(tweak.get("link", {}))
            snap["latency"]["gateway"].update(tweak.get("gateway", {}))
            r = analyze(snap)
            self.assertNoFinding(r, "speed_below_plan_provider")
            self.assertFinding(r, "speed_below_plan", "high")

    def test_strong_backhaul_and_ethernet_tip_agree(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -55})
        r = analyze(snap)
        strong = self.assertFinding(r, "satellite_backhaul_strong", "good")
        self.assertFinding(r, "use_ethernet_backhaul", "low")
        self.assertNotIn("Nothing to fix", " ".join(strong["how_to_fix"]))

    def test_local_loss_headline_names_a_wifi_fix(self):
        snap = perfect_snapshot()
        snap["latency"]["gateway"]["loss_pct"] = 5.0
        for t in snap["latency"]["internet"]:
            t["loss_pct"] = 5.0
        r = analyze(snap)
        self.assertEqual(r["bottleneck"], "wifi signal")
        self.assertNotIn("provider", r["headline"])

    def test_gadgets_already_on_iot_network_do_not_count_as_stuck_on_2g(self):
        snap = perfect_snapshot()
        clients = [_client(i, "band5") for i in range(5)]
        for i in range(5, 11):
            c = _client(i, "band2_4")
            c["interface"] = "iot"
            clients.append(c)
        snap["deco"]["clients"] = clients
        r = analyze(snap)
        self.assertNoFinding(r, "many_clients_on_2g")

    def test_fair_signal_is_not_called_weak(self):
        # -70 dBm is "okay" on the dashboard's signal guide; only below -75 is weak.
        snap = perfect_snapshot()
        snap["link"]["rssi_dbm"] = -70
        f = self.assertFinding(analyze(snap), "computer_weak_signal", "medium")
        self.assertNotIn("weak", f["title"])
        snap["link"]["rssi_dbm"] = -80
        f = self.assertFinding(analyze(snap), "computer_weak_signal", "high")
        self.assertIn("weak", f["title"])

    def test_hidden_flag_only_on_one_band_still_passes_checklist(self):
        # Real wlan answers often carry enable_hide_ssid on 2.4 GHz only.
        # The Deco app has ONE "Hide this network" switch for the network.
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["bands"]["band5"]["hidden"] = None
        snap["deco"]["wifi"]["bands"]["band6"]["hidden"] = None
        r = analyze(snap)
        self.assertFinding(r, "network_names_ok", "good")
        items = {c["id"]: c for c in r["checklist"]}
        self.assertEqual(items["no_hidden_network"]["status"], "pass")

    def test_slow_dns_on_computer_with_its_own_dns_servers(self):
        # If this computer asks a public DNS server directly, the Deco's DNS
        # setting won't change anything for it.
        snap = perfect_snapshot()
        snap["deco"]["wan"]["dns"] = ["192.168.1.1"]      # the provider's router
        snap["dns"].update({"median_ms": 150.0, "resolvers": ["75.75.75.75", "75.75.76.76"]})
        f = self.assertFinding(analyze(snap), "dns_slow", "medium")
        self.assertIn("this computer", f["how_to_fix"][0])
        self.assertIn("75.75.75.75", f["evidence"])
        # Normal case: the computer asks the Deco, so change the Deco's DNS.
        snap["dns"]["resolvers"] = ["192.168.68.1"]
        f = self.assertFinding(analyze(snap), "dns_slow", "medium")
        self.assertIn("Deco app", f["how_to_fix"][0])

    def test_main_deco_offline_advice_fits_the_main_unit(self):
        # The main Deco is cabled to the modem; "move it closer to another
        # Deco" is the wrong advice for it.
        snap = perfect_snapshot()
        snap["deco"]["nodes"][0]["online"] = False
        r = analyze(snap)
        f = self.assertFinding(r, "deco_offline", "critical")
        text = " ".join(f["how_to_fix"])
        self.assertNotIn("closer to another Deco", text)
        self.assertIn("modem", text)
        self.assertNotIn("placement", r["headline"])

    def test_slow_dns_does_not_suggest_servers_already_in_use(self):
        # The perfect snapshot's Deco already uses 1.1.1.1.
        snap = perfect_snapshot()
        snap["dns"].update({"median_ms": 150.0, "resolvers": ["192.168.68.1"]})
        f = self.assertFinding(analyze(snap), "dns_slow", "medium")
        self.assertNotIn("enter 1.1.1.1", " ".join(f["how_to_fix"]))
        self.assertIn("already", f["how_to_fix"][0])
        # This computer asks 1.1.1.1 itself.
        snap["deco"]["wan"]["dns"] = ["192.168.1.1"]
        snap["dns"]["resolvers"] = ["1.1.1.1"]
        f = self.assertFinding(analyze(snap), "dns_slow", "medium")
        self.assertNotIn("to 1.1.1.1", " ".join(f["how_to_fix"]))
        self.assertIn("already", f["how_to_fix"][0])

    def test_client_balance_skipped_when_per_deco_lists_failed(self):
        # deco_client stores errors["client_list_per_node"] when it could not
        # tell which Deco some devices use; the counts are then incomplete.
        snap = perfect_snapshot()
        for n, c in zip(snap["deco"]["nodes"], (20, 2, 1)):
            n["client_count"] = c
        self.assertFinding(analyze(snap), "client_load_unbalanced", "low")
        snap["deco"]["errors"] = {"client_list_per_node": "no answer for: Office"}
        self.assertNoFinding(analyze(snap), "client_load_unbalanced")

    def test_strong_signal_text_does_not_contradict_laggy_link(self):
        snap = perfect_snapshot()
        snap["latency"]["gateway"].update({"median_ms": 15.0})
        r = analyze(snap)
        self.assertFinding(r, "local_connection_unsteady", "medium")
        f = by_id(r).get("computer_signal_strong")
        if f is not None:
            self.assertNotIn("isn't holding", f["what_it_means"])

    def test_strong_backhaul_not_praised_when_link_is_slow(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -55}, rx={"band5": 300}, tx={"band5": 280})
        r = analyze(snap)
        self.assertFinding(r, "satellite_backhaul_slow_link", "medium")
        self.assertNoFinding(r, "satellite_backhaul_strong")

    def test_headline_with_medium_untagged_problem(self):
        snap = perfect_snapshot()
        snap["settings"]["plan_down_mbps"] = None
        snap["settings"]["plan_up_mbps"] = None
        snap["deco"]["performance"]["cpu_pct"] = 97.0
        r = analyze(snap)
        self.assertFinding(r, "main_deco_busy", "medium")
        self.assertEqual(r["bottleneck"], "none found")
        self.assertNotIn("Nothing big", r["headline"])
        self.assertIn("restart your main Deco", r["headline"])

    def test_plan_ceiling_headline_with_slow_upload(self):
        snap = perfect_snapshot()
        snap["speed"]["up_mbps"] = 10.0          # plan is 50 up
        r = analyze(snap)
        self.assertFinding(r, "plan_is_ceiling", "good")
        self.assertFinding(r, "upload_below_plan", "medium")
        self.assertIn("download", by_id(r)["plan_is_ceiling"]["title"])
        self.assertNotIn("only a faster plan", r["headline"])
        self.assertIn("upload", r["headline"])

    def test_checklist_does_not_ask_to_log_in_when_logged_in(self):
        snap = perfect_snapshot()
        snap["deco"]["nodes"] = []
        snap["deco"]["wifi"] = {"bands": {"band2_4": None, "band5": None, "band6": None},
                                "guest_enabled": None, "iot_enabled": None, "mlo_enabled": None,
                                "same_ssid_all_bands": None}
        snap["deco"]["wan"] = {k: None for k in snap["deco"]["wan"]}
        snap["deco"]["errors"] = {"device_list": "timeout", "wlan": "timeout", "wan_ipv4": "timeout"}
        r = analyze(snap)
        self.assertWellFormed(r)
        for item in r["checklist"]:
            self.assertNotIn("Log in", item["detail"], item["id"])

    def test_ethernet_tip_for_10g_model_mentions_cat6a(self):
        snap = wireless_sat(perfect_snapshot(), dbm={"band5": -55})
        for n in snap["deco"]["nodes"]:
            n["model"] = "BE85"
        f = self.assertFinding(analyze(snap), "use_ethernet_backhaul", "low")
        self.assertTrue(any("Cat6A" in s for s in f["how_to_fix"]), f["how_to_fix"])

    def test_mlo_tip_mentions_it_can_be_slower(self):
        # TP-Link FAQ 3911: MLO can be slower than one band on devices with
        # partial MLO support.
        snap = perfect_snapshot()
        snap["deco"]["wifi"]["mlo_enabled"] = False
        f = self.assertFinding(analyze(snap), "mlo_off", "low")
        self.assertTrue(any("slower" in s for s in f["how_to_fix"]), f["how_to_fix"])

    def test_bogus_wifi_gen_is_ignored(self):
        snap = perfect_snapshot()
        snap["link"]["wifi_gen"] = 0          # nonsense; phy says Wi-Fi 7
        r = analyze(snap)
        self.assertNoFinding(r, "computer_old_wifi")

    def test_negative_speed_is_ignored(self):
        snap = perfect_snapshot()
        snap["speed"]["down_mbps"] = -5.0
        snap["speed"]["up_mbps"] = -1.0
        r = analyze(snap)
        self.assertWellFormed(r)
        for fid in ("speed_below_plan", "speed_below_plan_provider", "upload_below_plan", "plan_is_ceiling"):
            self.assertNoFinding(r, fid)
        self.assertFalse(r["data_coverage"]["speed"])

    def test_ethernet_good_finding_is_hedged(self):
        snap = perfect_snapshot()
        snap["link"] = {k: None for k in snap["link"]}
        snap["link"].update({"os": "linux", "type": "ethernet", "interface": "eth0"})
        f = self.assertFinding(analyze(snap), "computer_on_ethernet", "good")
        self.assertIn("main Deco", f["what_it_means"])

    def test_access_point_mode_is_explained(self):
        snap = perfect_snapshot()
        snap["deco"]["wan"].update({"double_nat": True, "wan_ip": "192.168.1.20", "gateway": "192.168.1.1"})
        f = self.assertFinding(analyze(snap), "double_nat", "medium")
        ap = [s for s in f["how_to_fix"] if "Access Point mode" in s]
        self.assertTrue(ap)
        self.assertIn("only", ap[0])   # says what AP mode does

    CONTRADICTIONS = (
        ("satellite_backhaul_strong", ("satellite_wireless_backhaul_weak", "satellite_backhaul_2g_only",
                                       "satellite_backhaul_slow_link")),
        ("ethernet_backhaul_all", ("use_ethernet_backhaul", "satellite_daisy_chain")),
        ("channel_widths_ok", ("narrow_5ghz_channel", "narrow_6ghz_channel")),
        ("mlo_on", ("mlo_off",)),
        ("network_names_ok", ("hidden_network", "split_network_names")),
        ("no_double_nat", ("double_nat", "cgnat")),
        ("ipv6_on", ("ipv6_off",)),
        ("computer_on_ethernet", ("computer_weak_signal", "computer_low_snr", "computer_on_2g",
                                  "computer_old_wifi", "computer_low_link_rate", "computer_link_below_plan")),
        ("computer_signal_strong", ("computer_weak_signal", "computer_low_snr", "computer_on_2g",
                                    "computer_low_link_rate", "computer_link_below_plan")),
        ("plan_is_ceiling", ("speed_below_plan", "speed_below_plan_provider", "computer_link_below_plan")),
        ("speed_close_to_plan", ("speed_below_plan", "speed_below_plan_provider")),
        ("bufferbloat_ok", ("bufferbloat",)),
        ("gateway_latency_ok", ("local_connection_unsteady",)),
        ("dns_ok", ("dns_slow",)),
        ("rooms_even", ("weak_room",)),
        ("all_decos_online", ("deco_offline", "deco_internet_offline")),
        ("speed_below_plan_provider", ("computer_weak_signal", "computer_low_snr", "computer_on_2g",
                                       "computer_low_link_rate", "computer_link_below_plan",
                                       "local_connection_unsteady", "satellite_wireless_backhaul_weak",
                                       "satellite_backhaul_2g_only", "satellite_backhaul_slow_link")),
        ("client_load_unbalanced", ("deco_offline",)),
    )

    def random_snapshot(self, rng):
        snap = perfect_snapshot()
        nodes = snap["deco"]["nodes"]
        for n in nodes:
            n["model"] = rng.choice(["BE65", "BE85", "BE25", "X50", None])
            n["fw_version"] = rng.choice(["1.1.2", "1.1.2", "1.2.0"])
            n["client_count"] = rng.randint(0, 12)
            n["online"] = rng.random() > 0.1
            n["internet_online"] = rng.random() > 0.05
        for mac, parent in ((KIDS_MAC, MAIN_MAC), (OFFICE_MAC, rng.choice([MAIN_MAC, KIDS_MAC]))):
            if rng.random() < 0.6:
                band = rng.choice([("band5",), ("band6", "band5"), ("band2_4",), ("band2_4", "band5")])
                dbm = {b: rng.randint(-85, -45) for b in band} if rng.random() < 0.8 else None
                bars = {b: rng.randint(1, 5) for b in band} if dbm is None else None
                rate = {b: rng.choice([150, 350, 900, 2400]) for b in band if b != "band2_4"}
                wireless_sat(snap, mac=mac, name=mac[-2:], parent=parent, bands=band, dbm=dbm, bars=bars,
                             rx=rate, tx=rate)
        bands = snap["deco"]["wifi"]["bands"]
        bands["band5"].update({"enabled": rng.random() > 0.1, "width_mhz": rng.choice([20, 40, 80, 160, None])})
        bands["band6"].update({"enabled": rng.random() > 0.2, "width_mhz": rng.choice([80, 160, 320, None])})
        bands["band2_4"].update({"width_mhz": rng.choice([20, 40]), "hidden": rng.random() < 0.1})
        snap["deco"]["wifi"].update({"mlo_enabled": rng.choice([True, False, None]),
                                     "same_ssid_all_bands": rng.choice([True, False, None]),
                                     "iot_enabled": rng.choice([True, False, None])})
        nat = rng.choice([(False, False), (True, False), (False, True), (None, None)])
        snap["deco"]["wan"].update({"double_nat": nat[0], "cgnat": nat[1],
                                    "ipv6_enabled": rng.choice([True, False, None])})
        snap["deco"]["performance"] = {"cpu_pct": rng.choice([10, 85, 99]), "mem_pct": rng.choice([40, 95])}
        snap["deco"]["clients"] = [_client(i, rng.choice(["band2_4", "band5", "band6", "wired"]))
                                   for i in range(rng.randint(0, 15))]
        if rng.random() < 0.3:
            snap["link"] = {k: None for k in snap["link"]}
            snap["link"].update({"os": "linux", "type": "ethernet"})
        else:
            snap["link"].update({
                "band": rng.choice(["2.4GHz", "5GHz", "6GHz"]), "rssi_dbm": rng.randint(-85, -40),
                "snr_db": rng.choice([10, 25, 45]), "phy": rng.choice(["802.11be", "802.11ax", "802.11ac"]),
                "wifi_gen": None, "tx_rate_mbps": rng.choice([100.0, 300.0, 800.0, 2400.0]),
                "rx_rate_mbps": None})
        plan = rng.choice([100.0, 500.0, 1000.0, 2000.0, None])
        snap["settings"].update({"plan_down_mbps": plan, "plan_up_mbps": rng.choice([20.0, 100.0, None])})
        snap["speed"].update({"down_mbps": rng.choice([30.0, 90.0, 300.0, 470.0, 950.0, None]),
                              "up_mbps": rng.choice([5.0, 40.0, None]),
                              "bufferbloat_grade": rng.choice(["A+", "A", "B", "C", "D", "F", None])})
        snap["latency"]["gateway"].update({"median_ms": rng.choice([2.0, 12.0, 40.0]),
                                           "jitter_ms": rng.choice([0.5, 15.0]),
                                           "loss_pct": rng.choice([0.0, 3.0])})
        for t in snap["latency"]["internet"]:
            t["loss_pct"] = rng.choice([0.0, 0.0, 4.0])
        snap["dns"]["median_ms"] = rng.choice([10.0, 120.0, None])
        if rng.random() < 0.5:
            snap["history"].append({"room": "Attic", "down_mbps": rng.choice([20.0, 400.0]),
                                    "rssi_dbm": rng.randint(-85, -50)})
        return snap

    def test_random_snapshots_have_no_contradictions(self):
        import random
        rng = random.Random(20261125)
        for i in range(400):
            snap = self.random_snapshot(rng)
            r = analyze(snap)
            self.assertWellFormed(r)
            self.assertEqual(r["rule_errors"], [], i)
            ids = set(by_id(r))
            for good, bad in self.CONTRADICTIONS:
                if good in ids:
                    clash = ids.intersection(bad)
                    self.assertFalse(clash, "case %d: %s fired with %s" % (i, good, sorted(clash)))
            problems = [f for f in r["findings"] if f["severity"] in ("critical", "high", "medium")]
            if problems:
                self.assertNotIn("Nothing big", r["headline"], i)
                self.assertNotIn("looks great", r["headline"], i)

    def test_every_rule_survives_every_field_as_wrong_type(self):
        base = perfect_snapshot()
        odd_values = (None, "", "x", -1, 0, 1e309, [], {}, True)
        paths = []
        for k in base["link"]:
            paths.append(("link", k))
        for k in base["speed"]:
            paths.append(("speed", k))
        for k in base["deco"]["wifi"]:
            paths.append(("deco", "wifi", k))
        for k in base["deco"]["wan"]:
            paths.append(("deco", "wan", k))
        for k in base["deco"]["nodes"][1]:
            paths.append(("deco", "nodes", 1, k))
        for k in base["latency"]["gateway"]:
            paths.append(("latency", "gateway", k))
        for path in paths:
            for value in odd_values:
                snap = copy.deepcopy(base)
                target = snap
                for p in path[:-1]:
                    target = target[p]
                target[path[-1]] = value
                r = analyze(snap)
                self.assertEqual(r["rule_errors"], [], "%r=%r" % (path, value))
                json.dumps(r)


if __name__ == "__main__":
    unittest.main()
