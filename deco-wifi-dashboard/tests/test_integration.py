"""Integration tests: do the modules fit together the way SPEC.md says?

* Contract checks: every data shape that one module hands to another (demo
  data, ``DecoClient.fetch_all()`` against the fake Deco, the measure
  functions) has every key SPEC lists, and ``analyze()`` turns them into
  sensible findings.
* End to end: the real server (not demo mode) talks to ``tests.mock_deco``
  through the real ``DecoClient``, over HTTP, and no password ever comes back.

Nothing here touches the internet or a real Deco: the fake Deco, the speed
test server and the ping targets are all on 127.0.0.1, and DNS lookups use
"localhost".
"""

from __future__ import annotations

import base64
import copy
import functools
import http.client
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from decodash import analyze as analyze_mod  # noqa: E402
from decodash import deco_client, demo_data, server  # noqa: E402
from decodash.analyze import analyze  # noqa: E402
from decodash.measure import dns_check, latency, speedtest, wifi_link  # noqa: E402
from tests.mock_deco import BEDROOM_MAC, WIFI_PASSWORDS, MockDeco  # noqa: E402

# ---------------------------------------------------------------------------
# SPEC.md key lists ("Never omit a listed key")
# ---------------------------------------------------------------------------

SPEC_KEYS = {
    "snapshot": ("generated_at", "demo", "settings", "deco", "deco_error", "link", "latency", "speed",
                 "dns", "history"),
    "settings": ("deco_host", "plan_down_mbps", "plan_up_mbps", "room"),
    "deco": ("fetched_at", "nodes", "clients", "wifi", "wan", "performance", "errors", "raw"),
    "raw": ("device_list", "client_list", "wlan", "wan_ipv4", "performance", "ipv6"),
    "node": ("mac", "name", "model", "hw_version", "fw_version", "ip", "role", "online", "internet_online",
             "parent_mac", "backhaul", "backhaul_bands", "signal_dbm", "signal_bars", "rx_rate_mbps",
             "tx_rate_mbps", "backhaul_speed_mbps", "backhaul_max_mbps", "wired_ports", "client_count"),
    "client": ("mac", "name", "ip", "online", "band", "interface", "node_mac", "down_kbps", "up_kbps"),
    "wifi": ("bands", "guest_enabled", "iot_enabled", "mlo_enabled", "same_ssid_all_bands"),
    "band_cfg": ("enabled", "channel", "channel_width", "width_mhz", "mode", "backhaul_channel", "hidden"),
    "wan": ("wan_ip", "wan_mask", "gateway", "dial_type", "dns", "auto_dns", "lan_ip", "lan_mask",
            "double_nat", "cgnat", "ipv6_enabled"),
    "performance": ("cpu_pct", "mem_pct"),
    "link": ("os", "type", "interface", "ssid", "bssid", "band", "channel", "width_mhz", "phy", "wifi_gen",
             "rssi_dbm", "noise_dbm", "snr_db", "signal_pct", "tx_rate_mbps", "rx_rate_mbps", "error"),
    "target": ("name", "host", "port", "samples_ms", "median_ms", "p90_ms", "jitter_ms", "loss_pct"),
    "latency": ("gateway", "internet", "measured_at", "error"),
    "speed": ("down_mbps", "up_mbps", "idle_latency_ms", "loaded_latency_down_ms", "loaded_latency_up_ms",
              "bufferbloat_ms", "bufferbloat_grade", "server", "duration_s", "measured_at", "error"),
    "dns": ("median_ms", "samples", "resolvers", "measured_at", "error"),
    "dns_sample": ("host", "ms", "ok"),
    "room_test": ("room", "at", "down_mbps", "up_mbps", "latency_ms", "gateway_latency_ms", "rssi_dbm",
                  "band", "width_mhz", "phy", "bssid", "node_name"),
    "analysis": ("score", "grade", "headline", "bottleneck", "findings", "checklist", "data_coverage"),
    "finding": ("id", "severity", "category", "title", "what_it_means", "how_to_fix", "impact", "evidence"),
    "check": ("id", "title", "status", "detail", "how"),
    "coverage": ("deco", "link", "latency", "speed", "dns", "rooms"),
    "state": ("snapshot", "analysis", "jobs", "logged_in", "demo", "version"),
    "job": ("status", "progress", "message"),
}

SEVERITIES = ("critical", "high", "medium", "low", "good")
CATEGORIES = ("mesh", "wifi", "internet", "devices", "settings", "this computer")
IMPACTS = ("big", "medium", "small")
BOTTLENECKS = ("internet plan", "wifi signal", "mesh backhaul", "bufferbloat", "device", "dns",
               "none found", "not enough data")
CHECK_STATUSES = ("pass", "fail", "unknown", "manual")
BANDS = ("band2_4", "band5", "band6")


class SpecShapeMixin:
    """assertions that a dict carries every key SPEC.md lists for its shape."""

    def assertShape(self, kind, value, where=""):
        self.assertIsInstance(value, dict, "%s: %s should be a dict" % (where, kind))
        missing = [k for k in SPEC_KEYS[kind] if k not in value]
        self.assertEqual(missing, [], "%s: %s is missing %s" % (where, kind, missing))

    def assertDecoShape(self, deco, where):
        self.assertShape("deco", deco, where)
        self.assertShape("raw", deco["raw"], where)
        self.assertShape("performance", deco["performance"], where)
        self.assertShape("wan", deco["wan"], where)
        self.assertIsInstance(deco["wan"]["dns"], list)
        self.assertShape("wifi", deco["wifi"], where)
        for band in BANDS:
            self.assertIn(band, deco["wifi"]["bands"])
            cfg = deco["wifi"]["bands"][band]
            if cfg is not None:
                self.assertShape("band_cfg", cfg, "%s %s" % (where, band))
        self.assertIsInstance(deco["errors"], dict)
        self.assertTrue(deco["nodes"], where)
        self.assertEqual(deco["nodes"][0]["role"], "main", "%s: main node first" % where)
        for node in deco["nodes"]:
            self.assertShape("node", node, "%s node %s" % (where, node.get("name")))
            self.assertIn(node["role"], ("main", "satellite"))
            self.assertIn(node["backhaul"], ("wired", "wireless", "unknown", "n/a"))
            for key in ("signal_dbm", "signal_bars", "rx_rate_mbps", "tx_rate_mbps"):
                self.assertEqual(sorted(node[key]), sorted(BANDS), "%s %s" % (node["name"], key))
            self.assertIsInstance(node["client_count"], int)
        macs = {n["mac"] for n in deco["nodes"]}
        for client in deco["clients"]:
            self.assertShape("client", client, "%s client %s" % (where, client.get("name")))
            self.assertIn(client["band"], ("band2_4", "band5", "band6", "wired", "unknown"))
            if client["node_mac"] is not None:
                self.assertIn(client["node_mac"], macs, client["name"])

    def assertSnapshotShape(self, snap, where):
        self.assertShape("snapshot", snap, where)
        self.assertShape("settings", snap["settings"], where)
        if snap["deco"] is not None:
            self.assertDecoShape(snap["deco"], where)
        if snap["link"] is not None:
            self.assertShape("link", snap["link"], where)
        if snap["latency"] is not None:
            self.assertShape("latency", snap["latency"], where)
            if snap["latency"]["gateway"] is not None:
                self.assertShape("target", snap["latency"]["gateway"], where + " gateway")
            for target in snap["latency"]["internet"]:
                self.assertShape("target", target, where + " internet")
        if snap["speed"] is not None:
            self.assertShape("speed", snap["speed"], where)
        if snap["dns"] is not None:
            self.assertShape("dns", snap["dns"], where)
            for sample in snap["dns"]["samples"]:
                self.assertShape("dns_sample", sample, where)
        for entry in snap["history"]:
            self.assertShape("room_test", entry, where + " history")
        json.dumps(snap, allow_nan=False)  # plain JSON, no NaN

    def assertAnalysisShape(self, result, where):
        self.assertShape("analysis", result, where)
        self.assertShape("coverage", result["data_coverage"], where)
        self.assertEqual(result.get("rule_errors", []), [], "%s: a rule crashed" % where)
        self.assertIn(result["bottleneck"], BOTTLENECKS)
        self.assertIsInstance(result["headline"], str)
        self.assertTrue(result["headline"].strip())
        if result["score"] is not None:
            self.assertTrue(0 <= result["score"] <= 100)
            self.assertIn(result["grade"], ("A", "B", "C", "D", "F"))
        ids = []
        for f in result["findings"]:
            self.assertShape("finding", f, where)
            self.assertIn(f["severity"], SEVERITIES, f["id"])
            self.assertIn(f["category"], CATEGORIES, f["id"])
            self.assertIn(f["impact"], IMPACTS, f["id"])
            self.assertIsInstance(f["how_to_fix"], list)
            for text in (f["title"], f["what_it_means"], f["evidence"]) + tuple(f["how_to_fix"]):
                self.assertIsInstance(text, str, f["id"])
                for junk in ("None", "nan", "{", "%s", "%d"):
                    self.assertNotIn(junk, text, "%s: %r" % (f["id"], text))
            ids.append(f["id"])
        self.assertEqual(len(ids), len(set(ids)), "%s: duplicate finding ids" % where)
        order = [SEVERITIES.index(f["severity"]) for f in result["findings"]]
        self.assertEqual(order, sorted(order), "%s: findings sorted by severity" % where)
        for item in result["checklist"]:
            self.assertShape("check", item, where)
            self.assertIn(item["status"], CHECK_STATUSES, item["id"])
        json.dumps(result, allow_nan=False)


# ---------------------------------------------------------------------------
# Local stand-ins so the real measure code never leaves 127.0.0.1
# ---------------------------------------------------------------------------

_CHUNK = 64 * 1024
_ZEROS = b"\0" * _CHUNK


class _SpeedHandler(BaseHTTPRequestHandler):
    """A tiny speed.cloudflare.com: GET /__down?bytes=N and POST /__up."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path != "/__down":
            self.send_error(404)
            return
        size = int(parse_qs(parts.query).get("bytes", ["0"])[0])
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        left = size
        try:
            while left > 0:
                n = min(_CHUNK, left)
                self.wfile.write(_ZEROS[:n])
                left -= n
                time.sleep(0.002)
        except OSError:
            self.close_connection = True

    def do_POST(self):
        if urlsplit(self.path).path != "/__up":
            self.send_error(404)
            return
        left = int(self.headers.get("Content-Length") or 0)
        try:
            while left > 0:
                data = self.rfile.read(min(_CHUNK, left))
                if not data:
                    self.close_connection = True
                    return
                left -= len(data)
                time.sleep(0.002)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        except OSError:
            self.close_connection = True


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class OfflineMeasureMixin:
    """Start local ping/speed targets and point the measure modules at them.

    Works on the instance (setUp) or on the class (setUpClass).
    """

    def start_offline_targets(self):
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(64)
        ping_port = self._listener.getsockname()[1]
        self._speed = _QuietServer(("127.0.0.1", 0), _SpeedHandler)
        self._speed_thread = threading.Thread(target=self._speed.serve_forever,
                                              kwargs={"poll_interval": 0.05}, daemon=True)
        self._speed_thread.start()
        self.speed_base = "http://127.0.0.1:%d" % self._speed.server_address[1]
        real_speedtest = speedtest.run_speedtest
        self._patches = [
            mock.patch.object(latency, "INTERNET_TARGETS",
                              (("Cloudflare", "127.0.0.1", ping_port), ("Google", "127.0.0.1", ping_port))),
            mock.patch.object(dns_check, "POPULAR_HOSTS", ("localhost",)),
            mock.patch.object(dns_check, "UNCACHED_PARENTS", ()),
            # The server calls run_speedtest(progress_cb=...) with the default
            # Cloudflare URL; send it to the local server instead, and keep it short.
            mock.patch.object(speedtest, "run_speedtest",
                              functools.partial(real_speedtest, self.speed_base, seconds=1.5, streams=2,
                                                timeout=5.0)),
        ]
        for p in self._patches:
            p.start()

    def stop_offline_targets(self):
        for p in reversed(self._patches):
            p.stop()
        self._speed.shutdown()
        self._speed.server_close()
        self._speed_thread.join(5)
        self._listener.close()


def _fetch_mock_deco(**knobs):
    deco = MockDeco()
    for key, value in knobs.items():
        setattr(deco, key, value)
    base = deco.start()
    try:
        client = deco_client.DecoClient(base, deco.password, timeout=5)
        try:
            data = client.fetch_all()
        finally:
            client.logout()
    finally:
        deco.stop()
    return deco, base, data


def _secret_forms(values):
    """Each secret as typed, base64'd (how the Deco sends Wi-Fi passwords) and JSON-escaped."""
    forms = set()
    for value in values:
        if not value:
            continue
        forms.add(value)
        forms.add(base64.b64encode(value.encode("utf-8")).decode("ascii"))
        forms.add(json.dumps(value)[1:-1])
    return forms


# ---------------------------------------------------------------------------
# Step 2: contracts between modules
# ---------------------------------------------------------------------------

class ContractTests(SpecShapeMixin, OfflineMeasureMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock_deco, cls.mock_base, cls.deco = _fetch_mock_deco()
        OfflineMeasureMixin.start_offline_targets(cls)
        try:
            # Real measure calls, once (all of them stay on this computer).
            cls.link = wifi_link.get_link_info(timeout=8.0)
            cls.lat = latency.measure_latency("127.0.0.1", count=3, timeout=1.0)
            cls.dns = dns_check.measure_dns(timeout=3.0)
            cls.speed = speedtest.run_speedtest(progress_cb=lambda f, m: None)
        except BaseException:
            OfflineMeasureMixin.stop_offline_targets(cls)
            raise

    @classmethod
    def tearDownClass(cls):
        OfflineMeasureMixin.stop_offline_targets(cls)

    def mock_snapshot(self, **parts):
        snap = {
            "generated_at": "2026-11-25T12:00:00+00:00", "demo": False,
            "settings": {"deco_host": self.mock_base, "plan_down_mbps": 500.0, "plan_up_mbps": 50.0,
                         "room": "Desk"},
            "deco": copy.deepcopy(self.deco), "deco_error": None,
            "link": None, "latency": None, "speed": None, "dns": None, "history": [],
        }
        snap.update(parts)
        return snap

    # -- shapes --------------------------------------------------------------

    def test_demo_snapshot_has_every_spec_key(self):
        snap = demo_data.build_demo_snapshot()
        self.assertIs(snap["demo"], True)
        self.assertSnapshotShape(snap, "demo")
        nos = lambda *_a, **_k: None  # noqa: E731
        for room in (None, "Upstairs Bedroom", "Garden"):
            self.assertDecoShape(demo_data.simulate_deco(sleep=nos), "simulate_deco")
            self.assertShape("link", demo_data.simulate_link(room, sleep=nos), "simulate_link")
            self.assertShape("latency", demo_data.simulate_latency(room, sleep=nos), "simulate_latency")
            self.assertShape("dns", demo_data.simulate_dns(sleep=nos), "simulate_dns")
            self.assertShape("speed", demo_data.simulate_speed(room, progress_cb=lambda f, m: None, sleep=nos),
                             "simulate_speed")

    def test_mock_fetch_all_has_every_spec_key(self):
        self.assertEqual(self.mock_deco.violations, [])
        self.assertEqual(self.mock_deco.protocol_errors, [])
        self.assertEqual(self.deco["errors"], {})
        self.assertDecoShape(self.deco, "mock")
        names = [n["name"] for n in self.deco["nodes"]]
        self.assertEqual(names, ["Living Room", "Bedroom", "Office"])
        by_name = {n["name"]: n for n in self.deco["nodes"]}
        self.assertEqual(by_name["Bedroom"]["backhaul"], "wireless")
        self.assertEqual(by_name["Office"]["backhaul"], "wired")
        # Bedroom: Maya's iPhone, Sam's Pixel and the Kindle (the old iPad is offline).
        self.assertEqual(by_name["Bedroom"]["client_count"], 3)
        self.assertEqual(len(self.deco["clients"]), 9)
        self.assertEqual(sum(1 for c in self.deco["clients"] if c["online"]), 8)
        self.assertTrue(self.deco["wifi"]["mlo_enabled"])
        self.assertTrue(self.deco["wan"]["double_nat"])
        text = json.dumps(self.deco)
        for secret in _secret_forms(list(WIFI_PASSWORDS) + [self.mock_deco.password]):
            self.assertNotIn(secret, text)

    def test_real_measurements_have_every_spec_key(self):
        link = self.link
        self.assertShape("link", link, "get_link_info")
        self.assertIn(link["type"], ("wifi", "ethernet", "unknown"))
        lat = self.lat
        self.assertShape("latency", lat, "measure_latency")
        self.assertShape("target", lat["gateway"], "gateway")
        self.assertEqual(len(lat["internet"]), 2)
        for target in lat["internet"]:
            self.assertShape("target", target, "internet")
            self.assertEqual(target["host"], "127.0.0.1")  # stayed offline
            self.assertIsNotNone(target["median_ms"])
        dns = self.dns
        self.assertShape("dns", dns, "measure_dns")
        self.assertEqual([s["host"] for s in dns["samples"]], ["localhost"])
        speed = self.speed
        self.assertShape("speed", speed, "run_speedtest")
        self.assertIsNone(speed["error"], speed["error"])
        self.assertGreater(speed["down_mbps"], 0)
        self.assertGreater(speed["up_mbps"], 0)
        self.assertEqual(speed["server"], urlsplit(self.speed_base).netloc)

    # -- analyze() on what the other modules really produce ------------------

    def test_analyze_demo_snapshot(self):
        result = analyze(demo_data.build_demo_snapshot())
        self.assertAnalysisShape(result, "demo")
        cov = result["data_coverage"]
        self.assertTrue(all(cov[k] for k in ("deco", "link", "latency", "speed", "dns")), cov)
        self.assertGreaterEqual(cov["rooms"], 2)
        self.assertIsNotNone(result["score"])
        ids = {f["id"] for f in result["findings"]}
        # The demo home: a weak wireless satellite, 41% of a 1 Gbps plan, double NAT.
        for fid in ("satellite_wireless_backhaul_weak", "speed_below_plan", "double_nat", "weak_room"):
            self.assertIn(fid, ids)
        self.assertEqual(result["bottleneck"], "mesh backhaul")
        self.assertIn("Upstairs Bedroom", result["headline"])

    def test_analyze_mock_deco_with_real_measurements(self):
        link, lat, dns, speed = (copy.deepcopy(x) for x in (self.link, self.lat, self.dns, self.speed))
        snap = self.mock_snapshot(link=link, latency=lat, dns=dns, speed=speed)
        self.assertSnapshotShape(snap, "mock")
        result = analyze(copy.deepcopy(snap))
        self.assertAnalysisShape(result, "mock")
        cov = result["data_coverage"]
        self.assertTrue(cov["deco"] and cov["latency"] and cov["speed"] and cov["dns"], cov)
        self.assertEqual(cov["link"], link["type"] in ("wifi", "ethernet"))
        ids = {f["id"] for f in result["findings"]}
        # What the fake Deco's data should produce.
        expected = ("all_decos_online", "double_nat", "firmware_mismatch", "satellite_backhaul_strong",
                    "channel_widths_ok", "mlo_on", "network_names_ok", "use_ethernet_backhaul")
        for fid in expected:
            self.assertIn(fid, ids)
        for fid in ("deco_offline", "satellite_wireless_backhaul_weak", "mlo_off", "hidden_network",
                    "split_network_names", "cgnat", "need_speed_test", "need_quick_check"):
            self.assertNotIn(fid, ids)
        tip = [f for f in result["findings"] if f["id"] == "use_ethernet_backhaul"][0]
        self.assertIn("Bedroom", tip["title"])
        self.assertNotIn("Office", tip["title"])  # Office is already on a cable
        checks = {c["id"]: c["status"] for c in result["checklist"]}
        self.assertEqual(checks["ethernet_backhaul"], "fail")
        self.assertEqual(checks["strong_satellite_signal"], "pass")
        self.assertEqual(checks["mlo_on"], "pass")
        self.assertEqual(checks["firmware"], "fail")
        self.assertEqual(checks["no_double_nat"], "fail")
        self.assertEqual(checks["iot_network"], "pass")

    def test_analyze_mock_deco_without_measurements(self):
        result = analyze(self.mock_snapshot())
        self.assertAnalysisShape(result, "mock only")
        self.assertEqual(result["bottleneck"], "not enough data")
        self.assertIn("speed test", result["headline"])

    def test_per_node_error_key_is_the_one_analyze_reads(self):
        # analyze.rule_client_balance reads errors["client_list_per_node"] by name.
        self.assertEqual(deco_client.PER_NODE_KEY, "client_list_per_node")
        _mock, _base, deco = _fetch_mock_deco(fail_forms={"client_list:per_node": 500})
        self.assertIn("client_list_per_node", deco["errors"])
        snap = self.mock_snapshot(deco=deco)
        # Pile every device onto one Deco: without per-Deco lists, that's not evidence.
        for node in deco["nodes"]:
            node["client_count"] = 0
        deco["nodes"][1]["client_count"] = 12
        result = analyze(snap)
        self.assertAnalysisShape(result, "per-node failed")
        self.assertNotIn("client_load_unbalanced", {f["id"] for f in result["findings"]})

    def test_ethernet_link_speed_from_measure_is_used(self):
        # wifi_link reports a cable's link speed in tx/rx_rate_mbps (and link_speed_mbps).
        # A 100 Mbps cable on a 500 Mbps plan must not be blamed on the provider.
        link = {k: None for k in SPEC_KEYS["link"]}
        link.update({"os": "linux", "type": "ethernet", "interface": "eth0", "tx_rate_mbps": 100.0,
                     "rx_rate_mbps": 100.0, "link_speed_mbps": 100})
        lat = copy.deepcopy(self.lat)
        speed = copy.deepcopy(self.speed)
        speed["down_mbps"] = 94.0
        snap = self.mock_snapshot(link=link, latency=lat, speed=speed)
        result = analyze(snap)
        self.assertAnalysisShape(result, "slow cable")
        ids = {f["id"] for f in result["findings"]}
        self.assertIn("computer_ethernet_slow_link", ids)
        self.assertNotIn("speed_below_plan_provider", ids)
        self.assertNotIn("computer_on_ethernet", ids)
        self.assertEqual(result["bottleneck"], "device")
        # A gigabit cable on the same plan is fine.
        link.update({"tx_rate_mbps": 1000.0, "rx_rate_mbps": 1000.0, "link_speed_mbps": 1000})
        speed["down_mbps"] = 480.0
        ids = {f["id"] for f in analyze(snap)["findings"]}
        self.assertIn("computer_on_ethernet", ids)
        self.assertNotIn("computer_ethernet_slow_link", ids)

    def test_room_test_matches_mock_bssid_to_its_deco(self):
        link = {k: None for k in SPEC_KEYS["link"]}
        link.update({"os": "macos", "type": "wifi", "band": "5GHz", "rssi_dbm": -71,
                     "bssid": "a8:42:a1:3c:71:26", "width_mhz": 80, "phy": "802.11ax"})
        lat, speed = copy.deepcopy(self.lat), copy.deepcopy(self.speed)
        entry = server.build_room_test("Bedroom desk", link, lat, speed, self.deco["nodes"])
        self.assertShape("room_test", entry)
        self.assertEqual(entry["node_name"], "Bedroom")
        self.assertIsNotNone(entry["latency_ms"])
        self.assertIsNotNone(entry["gateway_latency_ms"])
        self.assertGreater(entry["down_mbps"], 0)
        result = analyze(self.mock_snapshot(link=link, latency=lat, speed=speed, history=[entry]))
        self.assertAnalysisShape(result, "room")
        self.assertEqual(result["data_coverage"]["rooms"], 1)

    # -- server <-> other modules --------------------------------------------

    def test_server_redaction_keeps_every_analyzer_input(self):
        # The server redacts the whole snapshot before analyze() sees it.
        for snap in (demo_data.build_demo_snapshot(), self.mock_snapshot()):
            redacted = server._redact(snap)
            if snap["deco"] is not None:
                snap = copy.deepcopy(snap)
                redacted = copy.deepcopy(redacted)
                snap["deco"].pop("raw")
                redacted["deco"].pop("raw")
            self.assertEqual(redacted, snap)

    def test_server_fallback_redaction_matches_deco_client(self):
        self.assertEqual(set(server._SECRET_PARTS), set(deco_client._SECRET_PARTS))
        self.assertEqual(server._SECRET_EXACT, deco_client._SECRET_EXACT)
        self.assertEqual(server._SECRET_WORDS, deco_client._SECRET_WORDS)
        sample = {k: "x" for k in ("password", "wifiKey", "wep_key1", "wifi_pass", "x-api-key", "private-key",
                                   "adminPw", "pinCode", "psk", "sysauth", "stok", "monkey", "keys", "ssid",
                                   "passive_scan", "channel", "Key", "guest_pass")}
        sample["nested"] = [{"wpa_key": "x", "name": "y"}]
        self.assertEqual(server._local_redact(sample), deco_client.redact(sample))
        raw = copy.deepcopy(self.mock_deco.fixtures)
        self.assertEqual(server._local_redact(raw), deco_client.redact(raw))

    def test_server_fallback_coverage_matches_analyzer(self):
        cases = [demo_data.build_demo_snapshot(), self.mock_snapshot()]
        partial = self.mock_snapshot(
            link={"os": "linux", "type": "unknown", "error": "no Wi-Fi"},
            latency={"gateway": None, "internet": [], "measured_at": "x", "error": "offline"},
            speed={"down_mbps": None, "up_mbps": None, "error": "offline"},
            dns={"median_ms": None, "samples": [], "resolvers": [], "error": "offline"},
        )
        cases.append(partial)
        for snap in cases:
            self.assertEqual(server._coverage(snap), analyze(snap)["data_coverage"])

    def test_validate_host_output_is_accepted_by_deco_client(self):
        for typed, base in (("127.0.0.1:8080", "http://127.0.0.1:8080"),
                            ("http://127.0.0.1:8080/", "http://127.0.0.1:8080"),
                            ("https://192.168.68.1", "https://192.168.68.1"),
                            ("192.168.68.1", "http://192.168.68.1"),
                            ("tplinkdeco.net", "http://tplinkdeco.net"),
                            ("fe80::1", "http://[fe80::1]"),
                            ("[fe80::1%en0]", "http://[fe80::1%en0]")):
            clean = server.validate_host(typed)
            self.assertEqual(deco_client.DecoClient(clean, "pw").base_url, base, typed)

    def test_analyze_module_has_spec_signature(self):
        # server calls analyze(snapshot) with a redacted deep copy; it must never raise.
        for broken in ({}, None, {"deco": "x", "link": 5, "history": "no"}):
            result = analyze_mod.analyze(broken)
            self.assertShape("analysis", result, repr(broken))


# ---------------------------------------------------------------------------
# Step 3: real server + real DecoClient + fake Deco, over HTTP
# ---------------------------------------------------------------------------

class EndToEndMockDecoTests(SpecShapeMixin, OfflineMeasureMixin, unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="decodash-integration-")
        self.env = mock.patch.dict(os.environ, {"DECODASH_HOME": self.tmp})
        self.env.start()
        self.start_offline_targets()
        self.deco = MockDeco()
        self.deco_base = self.deco.start()
        self.deco_hostport = self.deco_base.split("://", 1)[1]  # "127.0.0.1:<port>"
        self.server = server.make_server(0, demo=False, history_path=Path(self.tmp) / "history.json")
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.port = self.server.port
        self.bodies = []
        self.secrets = list(WIFI_PASSWORDS) + [self.deco.password]

    def tearDown(self):
        self.wait_idle(30)
        self.server.shutdown()
        self.server.server_close()
        self.server.state.close()
        self.thread.join(5)
        self.deco.stop()
        self.stop_offline_targets()
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        headers = {"X-Dash-Token": self.server.token}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8")
        finally:
            conn.close()
        self.bodies.append(raw)
        return resp.status, json.loads(raw)

    def wait_idle(self, timeout=60.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.server.state.lock:
                if not any(j["status"] == "running" for j in self.server.state.jobs.values()):
                    return True
            time.sleep(0.05)
        return False

    def assertNoSecretsAnywhere(self, extra=()):
        forms = _secret_forms(self.secrets + [s for s in extra if s])
        for body in self.bodies:
            for secret in forms:
                self.assertNotIn(secret, body)
        for path in Path(self.tmp).rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="replace")
                for secret in forms:
                    self.assertNotIn(secret, text, path.name)

    def login(self, host=None):
        return self.call("POST", "/api/login", {"host": host or self.deco_hostport,
                                                "password": self.deco.password})

    def test_login_state_quick_run_and_no_secrets(self):
        status, state = self.login()
        self.assertEqual(status, 200, state)
        self.assertTrue(state["logged_in"])
        self.assertFalse(state["demo"])
        self.assertTrue(self.deco.session_active)
        session = [self.deco.current_stok, self.deco.current_sysauth]
        self.assertTrue(all(session))

        status, state = self.call("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertShape("state", state)
        self.assertEqual(sorted(state["jobs"]), sorted(server.JOB_NAMES))
        for job in state["jobs"].values():
            self.assertShape("job", job)
        snap = state["snapshot"]
        self.assertSnapshotShape(snap, "state")
        self.assertEqual(snap["settings"]["deco_host"], self.deco_hostport)
        self.assertEqual([n["name"] for n in snap["deco"]["nodes"]], ["Living Room", "Bedroom", "Office"])
        self.assertEqual(len(snap["deco"]["clients"]), 9)
        self.assertEqual(state["jobs"]["deco"]["status"], "done")
        self.assertIn("3 Decos and 8 devices", state["jobs"]["deco"]["message"])
        self.assertAnalysisShape(state["analysis"], "after login")
        self.assertTrue(state["analysis"]["data_coverage"]["deco"])
        self.assertIn("firmware_mismatch", {f["id"] for f in state["analysis"]["findings"]})

        status, state = self.call("POST", "/api/run", {"what": "quick"})
        self.assertEqual(status, 200, state)
        self.assertTrue(self.wait_idle(60), "quick run didn't finish")
        status, state = self.call("GET", "/api/state")
        jobs = state["jobs"]
        for name in ("deco", "latency", "dns"):
            self.assertEqual(jobs[name]["status"], "done", (name, jobs[name]))
        self.assertIn(jobs["link"]["status"], ("done", "error"), jobs["link"])
        self.assertTrue(jobs["link"]["message"])
        self.assertEqual(jobs["speed"]["status"], "idle")  # quick = deco+link+latency+dns
        snap = state["snapshot"]
        self.assertSnapshotShape(snap, "after quick")
        self.assertEqual(snap["latency"]["gateway"]["host"], "127.0.0.1")
        analysis = state["analysis"]
        self.assertAnalysisShape(analysis, "after quick")
        cov = analysis["data_coverage"]
        self.assertTrue(cov["deco"] and cov["latency"] and cov["dns"], cov)
        self.assertFalse(cov["speed"])
        ids = {f["id"] for f in analysis["findings"]}
        self.assertIn("double_nat", ids)
        self.assertIn("need_speed_test", ids)
        # The quick run re-read the Deco with the same session: no second login.
        self.assertEqual(self.deco.counters["login_ok"], 1)
        self.assertEqual(self.deco.counters["unauthorized"], 0)

        status, export = self.call("GET", "/api/export")
        self.assertEqual(status, 200)
        self.assertSnapshotShape(export["snapshot"], "export")

        self.assertEqual(self.deco.violations, [])
        self.assertEqual(self.deco.protocol_errors, [])
        self.assertNoSecretsAnywhere(extra=session)

        status, state = self.call("POST", "/api/logout")
        self.assertEqual(status, 200)
        self.assertFalse(state["logged_in"])
        self.assertFalse(self.deco.session_active)
        self.assertEqual(self.call("POST", "/api/run", {"what": "deco"})[0], 400)

    def test_login_with_url_form_and_room_test(self):
        status, state = self.login(self.deco_base)
        self.assertEqual(status, 200, state)
        status, state = self.call("POST", "/api/room-test", {"room": "Kitchen"})
        self.assertEqual(status, 200, state)
        self.assertTrue(self.wait_idle(60), "room test didn't finish")
        status, state = self.call("GET", "/api/state")
        self.assertEqual(state["jobs"]["room"]["status"], "done", state["jobs"]["room"])
        self.assertEqual(state["jobs"]["speed"]["status"], "done", state["jobs"]["speed"])
        history = state["snapshot"]["history"]
        self.assertEqual(len(history), 1)
        self.assertShape("room_test", history[0])
        self.assertEqual(history[0]["room"], "Kitchen")
        self.assertGreater(history[0]["down_mbps"], 0)
        self.assertTrue(state["analysis"]["data_coverage"]["speed"])
        self.assertEqual(state["analysis"]["data_coverage"]["rooms"], 1)
        saved = json.loads((Path(self.tmp) / "history.json").read_text(encoding="utf-8"))
        self.assertEqual([e["room"] for e in saved], ["Kitchen"])
        self.assertNoSecretsAnywhere()

    def test_wrong_password_is_401_and_not_echoed(self):
        wrong = "not-the-password-123"
        self.secrets.append(wrong)
        status, body = self.call("POST", "/api/login", {"host": self.deco_hostport, "password": wrong})
        self.assertEqual(status, 401, body)
        self.assertIn("error", body)
        status, state = self.call("GET", "/api/state")
        self.assertFalse(state["logged_in"])
        self.assertIsNone(state["snapshot"]["deco"])
        self.assertTrue(state["snapshot"]["deco_error"])
        self.assertEqual(state["jobs"]["deco"]["status"], "error")
        self.assertFalse(self.deco.session_active)
        self.assertNoSecretsAnywhere()


if __name__ == "__main__":
    unittest.main()
