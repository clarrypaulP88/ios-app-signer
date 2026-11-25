"""Tests for decodash.server, decodash.demo_data, run.py and the web UI files.

These start the real HTTP server on 127.0.0.1 with a free port. Demo mode is
used for anything that would measure, and the Deco client is swapped for a
fake, so nothing here touches the internet or a real Deco.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from decodash import __version__, demo_data, server  # noqa: E402

WEB = ROOT / "decodash" / "web"


# ---------------------------------------------------------------------------
# A fake deco_client module
# ---------------------------------------------------------------------------

class FakeDecoError(Exception):
    pass


class FakeDecoAuthError(FakeDecoError):
    pass


class FakeDecoUnsupportedFirmware(FakeDecoError):
    pass


class FakeDecoConnectionError(FakeDecoError):
    pass


def fake_deco_module(behaviour):
    """A stand-in for decodash.deco_client. ``behaviour`` is an exception or 'ok'."""
    created = []

    class FakeClient:
        def __init__(self, host, password, username="admin", timeout=15.0):
            self.host = server._host_only(host)
            self._password = password
            self.logged_out = 0
            created.append(self)

        def fetch_all(self):
            if isinstance(behaviour, BaseException):
                raise behaviour
            data = demo_data.build_demo_deco()
            data.pop("demo", None)
            return data

        def logout(self):
            self.logged_out += 1

    module = types.SimpleNamespace(
        DecoClient=FakeClient,
        DecoError=FakeDecoError,
        DecoAuthError=FakeDecoAuthError,
        DecoUnsupportedFirmware=FakeDecoUnsupportedFirmware,
        DecoConnectionError=FakeDecoConnectionError,
        created=created,
    )
    return module


# ---------------------------------------------------------------------------
# Test base: a running server in a thread
# ---------------------------------------------------------------------------

class ServerCase(unittest.TestCase):
    demo = True

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="decodash-test-")
        self.env = mock.patch.dict(os.environ, {"DECODASH_HOME": self.tmp})
        self.env.start()
        self.server = server.make_server(0, demo=self.demo, demo_delay=0.01)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.port = self.server.port
        self.token = self.server.token

    def tearDown(self):
        self.wait_idle(timeout=10)
        self.server.shutdown()
        self.server.server_close()
        self.server.state.close()
        self.thread.join(5)
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers ---------------------------------------------------------

    def request(self, method, path, body=None, token=True, headers=None, raw_body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        hdrs = {}
        if token:
            hdrs["X-Dash-Token"] = self.token
        data = raw_body
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        try:
            conn.request(method, path, body=data, headers=hdrs)
            resp = conn.getresponse()
            payload = resp.read()
            return resp.status, dict((k.lower(), v) for k, v in resp.getheaders()), payload
        finally:
            conn.close()

    def get_json(self, method, path, body=None, **kw):
        status, headers, payload = self.request(method, path, body, **kw)
        return status, json.loads(payload.decode("utf-8"))

    def wait_idle(self, timeout=15.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.server.state.lock:
                running = [n for n, j in self.server.state.jobs.items() if j["status"] == "running"]
            if not running:
                return True
            time.sleep(0.05)
        return False


class SecurityTests(ServerCase):
    def test_api_requires_token(self):
        status, _h, _b = self.request("GET", "/api/state", token=False)
        self.assertEqual(status, 403)
        status, _h, _b = self.request("POST", "/api/run", {"what": "quick"}, token=False)
        self.assertEqual(status, 403)
        status, _h, _b = self.request("GET", "/api/state", token=False,
                                      headers={"X-Dash-Token": "wrong-token"})
        self.assertEqual(status, 403)

    def test_bad_host_header_is_refused(self):
        status, _h, _b = self.request("GET", "/api/state", headers={"Host": "evil.example"})
        self.assertEqual(status, 403)
        status, _h, body = self.request("GET", "/", headers={"Host": "evil.example:%d" % self.port})
        self.assertEqual(status, 403)
        self.assertNotIn(self.token.encode(), body)

    def test_localhost_host_header_is_fine(self):
        status, _h, _b = self.request("GET", "/api/state", headers={"Host": "localhost:%d" % self.port})
        self.assertEqual(status, 200)

    def test_foreign_origin_is_refused(self):
        status, _h, _b = self.request("POST", "/api/run", {"what": "dns"},
                                      headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        status, _h, _b = self.request("POST", "/api/settings", {"room": "Den"},
                                      headers={"Origin": "http://127.0.0.1:%d" % self.port})
        self.assertEqual(status, 200)

    def test_static_traversal_blocked(self):
        for path in ("/static/../server.py", "/static/%2e%2e/server.py", "/static/..%2fserver.py",
                     "/static/.hidden", "/static/../../run.py", "/static/%2fetc%2fpasswd"):
            status, _h, body = self.request("GET", path)
            self.assertIn(status, (400, 403, 404), path)
            self.assertNotIn(b"ThreadingHTTPServer", body, path)
            self.assertNotIn(b"import", body, path)

    def test_static_files_have_types_and_no_store(self):
        expected = {"/static/app.js": "javascript", "/static/style.css": "text/css"}
        for path, ctype in expected.items():
            status, headers, body = self.request("GET", path)
            self.assertEqual(status, 200, path)
            self.assertIn(ctype, headers.get("content-type", ""))
            self.assertEqual(headers.get("cache-control"), "no-store")
            self.assertEqual(headers.get("x-content-type-options"), "nosniff")
            self.assertTrue(body)

    def test_index_has_token(self):
        status, headers, body = self.request("GET", "/", token=False)
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn(self.token, text)
        self.assertNotIn("__DASH_TOKEN__", text)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertEqual(headers.get("cache-control"), "no-store")
        self.assertIn("default-src 'none'", headers.get("content-security-policy", ""))

    def test_tokens_differ_per_server(self):
        other = server.make_server(0, demo=True)
        try:
            self.assertNotEqual(other.token, self.token)
            self.assertGreaterEqual(len(other.token), 24)
        finally:
            other.server_close()

    def test_body_size_capped(self):
        big = b'{"room": "' + b"x" * (70 * 1024) + b'"}'
        status, _h, body = self.request("POST", "/api/settings", raw_body=big,
                                        headers={"Content-Type": "application/json"})
        self.assertEqual(status, 413)
        self.assertIn(b"error", body)

    def test_bad_json_and_unknowns(self):
        status, _h, body = self.request("POST", "/api/settings", raw_body=b"{nope",
                                        headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertIn("error", json.loads(body))
        status, _h, _b = self.request("POST", "/api/settings", raw_body=b"[1, 2]",
                                      headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        status, data = self.get_json("GET", "/api/nope")
        self.assertEqual(status, 404)
        self.assertIn("error", data)
        status, _h, _b = self.request("GET", "/api/run")
        self.assertEqual(status, 405)
        status, data = self.get_json("POST", "/api/run", {"what": "everything"})
        self.assertEqual(status, 400)
        status, _h, _b = self.request("GET", "/nothing-here")
        self.assertEqual(status, 404)


class StateTests(ServerCase):
    def test_state_shape(self):
        status, data = self.get_json("GET", "/api/state")
        self.assertEqual(status, 200)
        for key in ("snapshot", "analysis", "jobs", "logged_in", "demo", "version"):
            self.assertIn(key, data)
        self.assertTrue(data["demo"])
        self.assertTrue(data["snapshot"]["demo"])
        self.assertEqual(data["version"], __version__)
        self.assertEqual(sorted(data["jobs"]), sorted(server.JOB_NAMES))
        for job in data["jobs"].values():
            self.assertEqual(set(job), {"status", "progress", "message"})
            self.assertEqual(job["status"], "idle")
        for key in ("generated_at", "demo", "settings", "deco", "deco_error", "link", "latency",
                    "speed", "dns", "history"):
            self.assertIn(key, data["snapshot"])
        self.assertIsInstance(data["analysis"], dict)
        self.assertEqual(data["link_node_name"], "Office")

    def test_analysis_error_gives_note_not_500(self):
        def broken():
            def analyze(_snapshot):
                raise RuntimeError("boom")
            return analyze

        with mock.patch.object(server, "_analyze_func", broken):
            status, data = self.get_json("GET", "/api/state")
        self.assertEqual(status, 200)
        analysis = data["analysis"]
        self.assertIsNone(analysis["score"])
        self.assertIn("boom", analysis["error"])
        self.assertEqual(analysis["bottleneck"], "not enough data")
        self.assertTrue(analysis["data_coverage"]["deco"])
        self.assertEqual(analysis["data_coverage"]["rooms"], 4)

    def test_quick_run_finishes(self):
        status, data = self.get_json("POST", "/api/run", {"what": "quick"})
        self.assertEqual(status, 200)
        self.assertEqual(data["jobs"]["link"]["status"], "running")
        self.assertTrue(self.wait_idle())
        status, data = self.get_json("GET", "/api/state")
        for name in ("deco", "link", "latency", "dns"):
            self.assertEqual(data["jobs"][name]["status"], "done", data["jobs"][name])
            self.assertEqual(data["jobs"][name]["progress"], 1.0)
        self.assertEqual(data["jobs"]["speed"]["status"], "idle")
        self.assertEqual(data["snapshot"]["link"]["type"], "wifi")

    def test_full_run_includes_speed_with_progress(self):
        seen = []
        original = server.DashState._progress

        def spy(self_, name, fraction, message=None):
            if name == "speed":
                seen.append(fraction)
            return original(self_, name, fraction, message)

        with mock.patch.object(server.DashState, "_progress", spy):
            status, _data = self.get_json("POST", "/api/run", {"what": "all"})
            self.assertEqual(status, 200)
            self.assertTrue(self.wait_idle())
        status, data = self.get_json("GET", "/api/state")
        self.assertEqual(data["jobs"]["speed"]["status"], "done")
        self.assertTrue(seen, "the speed job should forward progress")
        self.assertIsNotNone(data["snapshot"]["speed"]["down_mbps"])

    def test_same_job_not_started_twice(self):
        state = self.server.state
        first = state._claim(["speed"])
        try:
            self.assertEqual(first, ["speed"])
            self.assertEqual(state._claim(["speed", "dns"]), ["dns"])
            status, data = self.get_json("POST", "/api/room-test", {"room": "Hall"})
            self.assertEqual(status, 409)
            self.assertIn("error", data)
        finally:
            for name in ("speed", "dns"):
                state._set_job(name, "idle", 0.0, "")
            self.assertTrue(self.wait_idle(timeout=2))

    def test_room_test_saves_history(self):
        status, data = self.get_json("GET", "/api/state")
        before = len(data["snapshot"]["history"])
        status, data = self.get_json("POST", "/api/room-test", {"room": "  Garage  "})
        self.assertEqual(status, 200)
        self.assertEqual(data["jobs"]["room"]["status"], "running")
        self.assertTrue(self.wait_idle())
        status, data = self.get_json("GET", "/api/state")
        self.assertEqual(data["jobs"]["room"]["status"], "done", data["jobs"]["room"])
        history = data["snapshot"]["history"]
        self.assertEqual(len(history), before + 1)
        entry = history[-1]
        self.assertEqual(entry["room"], "Garage")
        self.assertEqual(set(entry), set(server.ROOM_TEST_KEYS))
        self.assertIsNotNone(entry["down_mbps"])
        self.assertIsNotNone(entry["rssi_dbm"])
        self.assertIsNotNone(entry["node_name"])
        self.assertEqual(data["snapshot"]["settings"]["room"], "Garage")

        # Saved inside the temp DECODASH_HOME; demo rooms never go into the real history file.
        saved = json.loads((Path(self.tmp) / "demo-history.json").read_text("utf-8"))
        self.assertEqual(saved[-1]["room"], "Garage")
        self.assertFalse((Path(self.tmp) / "history.json").exists())

        status, data = self.get_json("POST", "/api/history/clear", {})
        self.assertEqual(status, 200)
        self.assertEqual(data["snapshot"]["history"], [])

    def test_room_test_needs_a_name(self):
        self.server.state.snapshot["settings"]["room"] = None
        status, data = self.get_json("POST", "/api/room-test", {"room": "   "})
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_settings(self):
        status, data = self.get_json("POST", "/api/settings",
                                     {"plan_down_mbps": "500", "plan_up_mbps": 25, "room": "Den",
                                      "deco_host": "http://192.168.68.1/"})
        self.assertEqual(status, 200)
        settings = data["snapshot"]["settings"]
        self.assertEqual(settings["plan_down_mbps"], 500.0)
        self.assertEqual(settings["plan_up_mbps"], 25.0)
        self.assertEqual(settings["room"], "Den")
        self.assertEqual(settings["deco_host"], "http://192.168.68.1")
        status, data = self.get_json("POST", "/api/settings", {"plan_down_mbps": None})
        self.assertIsNone(data["snapshot"]["settings"]["plan_down_mbps"])
        for bad in ({"plan_down_mbps": "fast"}, {"plan_up_mbps": -5}, {"plan_up_mbps": True},
                    {"deco_host": "http://192.168.68.1/admin"}, {"room": 42}):
            status, data = self.get_json("POST", "/api/settings", bad)
            self.assertEqual(status, 400, bad)
            self.assertIn("error", data)

    def test_export_has_no_secrets(self):
        secret = "hunter2-Very-Secret"
        status, data = self.get_json("POST", "/api/login", {"host": "192.168.68.1", "password": secret})
        self.assertEqual(status, 200)
        status, headers, body = self.request("GET", "/api/export")
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers.get("content-disposition", ""))
        self.assertNotIn(secret.encode(), body)
        data = json.loads(body)
        self.assertIn("snapshot", data)
        self.assertIn("analysis", data)

        found = []

        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if "password" in str(k).lower():
                        found.append(v)
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(data)
        self.assertTrue(all(v in ("***", None) for v in found), found)
        _status, _h, state_body = self.request("GET", "/api/state")
        self.assertNotIn(secret.encode(), state_body)

    def test_demo_login_logout(self):
        status, data = self.get_json("POST", "/api/logout", {})
        self.assertEqual(status, 200)
        self.assertFalse(data["logged_in"])
        status, data = self.get_json("POST", "/api/run", {"what": "deco"})
        self.assertEqual(status, 400)
        status, data = self.get_json("POST", "/api/login", {"host": "192.168.68.1", "password": "x"})
        self.assertEqual(status, 200)
        self.assertTrue(data["logged_in"])
        status, data = self.get_json("POST", "/api/login", {"host": "192.168.68.1", "password": ""})
        self.assertEqual(status, 400)


class RealModeTests(ServerCase):
    """Not demo mode. Only login/logout/settings are used (they don't measure)."""

    demo = False

    def test_initial_state(self):
        status, data = self.get_json("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertFalse(data["demo"])
        self.assertFalse(data["logged_in"])
        self.assertFalse(data["snapshot"]["demo"])
        self.assertIsNone(data["snapshot"]["deco"])
        self.assertEqual(data["snapshot"]["history"], [])
        self.assertEqual(data["snapshot"]["settings"]["deco_host"], "192.168.68.1")

    def login_with(self, behaviour, password="pw-123"):
        module = fake_deco_module(behaviour)
        with mock.patch.object(server, "_deco_module", lambda: module):
            status, data = self.get_json("POST", "/api/login", {"host": "192.168.68.1", "password": password})
        return status, data, module

    def test_login_auth_error_is_401(self):
        status, data, module = self.login_with(FakeDecoAuthError("That password didn't work."))
        self.assertEqual(status, 401)
        self.assertEqual(data, {"error": "That password didn't work."})
        self.assertEqual(module.created[0].logged_out, 1)
        self.assertIsNone(self.server.state.client)
        status, data = self.get_json("GET", "/api/state")
        self.assertFalse(data["logged_in"])
        self.assertEqual(data["jobs"]["deco"]["status"], "error")
        self.assertEqual(data["snapshot"]["deco_error"], "That password didn't work.")

    def test_login_other_errors(self):
        status, data, _m = self.login_with(FakeDecoUnsupportedFirmware("old firmware"))
        self.assertEqual(status, 400)
        self.assertIn("old firmware", data["error"])
        status, data, _m = self.login_with(FakeDecoConnectionError(""))
        self.assertEqual(status, 502)
        self.assertIn("192.168.68.1", data["error"])
        with mock.patch.object(server, "_log"):
            status, data, _m = self.login_with(ValueError("pw-123 leaked?"))
        self.assertEqual(status, 500)
        self.assertNotIn("pw-123", data["error"])

    def test_password_never_echoed_in_errors(self):
        status, data, _m = self.login_with(FakeDecoAuthError("bad pw-123"), password="pw-123")
        self.assertEqual(status, 401)
        self.assertNotIn("pw-123", data["error"])

    def test_login_bad_host(self):
        for host in ("javascript:alert(1)", "http://192.168.68.1/x?y", "a b", "", "ftp://192.168.68.1"):
            module = fake_deco_module("ok")
            with mock.patch.object(server, "_deco_module", lambda: module):
                status, data = self.get_json("POST", "/api/login", {"host": host, "password": "pw"})
            self.assertEqual(status, 400, host)
            self.assertEqual(module.created, [], host)

    def test_login_success_and_logout(self):
        status, data, module = self.login_with("ok")
        self.assertEqual(status, 200)
        self.assertTrue(data["logged_in"])
        self.assertEqual(len(data["snapshot"]["deco"]["nodes"]), 3)
        self.assertEqual(data["jobs"]["deco"]["status"], "done")
        self.assertNotIn("pw-123", json.dumps(data))
        settings_file = Path(self.tmp) / "settings.json"
        self.assertTrue(settings_file.exists())
        self.assertNotIn("pw-123", settings_file.read_text("utf-8"))
        client = module.created[0]

        status, data = self.get_json("POST", "/api/logout", {})
        self.assertEqual(status, 200)
        self.assertFalse(data["logged_in"])
        self.assertEqual(client.logged_out, 1)
        self.assertIsNotNone(data["snapshot"]["deco"], "the last data stays visible")

    def test_close_logs_out(self):
        _status, _data, module = self.login_with("ok")
        self.assertTrue(self.server.state.close())
        self.assertEqual(module.created[0].logged_out, 1)
        self.assertFalse(self.server.state.close())

    def test_run_deco_needs_login(self):
        status, data = self.get_json("POST", "/api/run", {"what": "deco"})
        self.assertEqual(status, 400)
        self.assertIn("error", data)


class HelperTests(unittest.TestCase):
    def test_validate_host(self):
        ok = {
            "192.168.68.1": "192.168.68.1",
            " 192.168.68.1 ": "192.168.68.1",
            "http://192.168.68.1": "http://192.168.68.1",
            "HTTPS://192.168.68.1/": "https://192.168.68.1",
            "192.168.68.1:8080": "192.168.68.1:8080",
            "tplinkdeco.net": "tplinkdeco.net",
            "Deco.Local": "deco.local",
            "[fe80::1]": "[fe80::1]",
        }
        for given, expected in ok.items():
            self.assertEqual(server.validate_host(given), expected, given)
        for bad in ("", "   ", None, 42, "http://", "192.168.68.1/admin", "user@192.168.68.1",
                    "javascript:alert(1)", "ftp://192.168.68.1", "1.2.3.4; rm -rf /", "999.1.1.1",
                    "0.0.0.0", "-bad-.com", "192.168.68.1:99999", "a" * 300):
            with self.assertRaises(server.ApiError, msg=repr(bad)):
                server.validate_host(bad)

    def test_match_node_name(self):
        nodes = demo_data.build_demo_deco()["nodes"]
        self.assertEqual(server.match_node_name("A8:42:A1:3C:5E:80", nodes), "Living Room")
        self.assertEqual(server.match_node_name("a8-42-a1-3c-63-f3", nodes), "Office")
        # differs only in the last hex digit
        self.assertEqual(server.match_node_name("A8:42:A1:3C:61:2B", nodes), "Upstairs Bedroom")
        # locally-administered variant of the first byte
        self.assertEqual(server.match_node_name("AA:42:A1:3C:5E:8C", nodes), "Living Room")
        self.assertIsNone(server.match_node_name("11:22:33:44:55:66", nodes))
        self.assertIsNone(server.match_node_name(None, nodes))
        self.assertIsNone(server.match_node_name("not a mac", nodes))
        plain = [{"name": "Kids", "mac": "F0:09:0D:FA:29:84"}]
        self.assertEqual(server.match_node_name("F0:09:0D:FA:29:86", plain), "Kids")

    def test_build_room_test(self):
        snap = demo_data.build_demo_snapshot()
        entry = server.build_room_test("Office", snap["link"], snap["latency"], snap["speed"],
                                       snap["deco"]["nodes"])
        self.assertEqual(set(entry), set(server.ROOM_TEST_KEYS))
        self.assertEqual(entry["down_mbps"], 412.0)
        self.assertEqual(entry["rssi_dbm"], -63)
        self.assertEqual(entry["node_name"], "Office")
        self.assertEqual(entry["band"], "6GHz")
        self.assertIsNotNone(entry["latency_ms"])
        empty = server.build_room_test("Hall", None, None, None)
        self.assertEqual(empty["room"], "Hall")
        self.assertIsNone(empty["down_mbps"])
        self.assertIsNone(empty["node_name"])

    def test_history_roundtrip(self):
        tmp = tempfile.mkdtemp(prefix="decodash-hist-")
        try:
            path = Path(tmp) / "sub" / "history.json"
            self.assertEqual(server.load_history(path), [])
            items = [server.build_room_test("Room %d" % i, None, None, None) for i in range(130)]
            server.save_history(path, items)
            loaded = server.load_history(path)
            self.assertEqual(len(loaded), server.MAX_HISTORY)
            self.assertEqual(loaded[-1]["room"], "Room 129")
            self.assertEqual([p.name for p in path.parent.iterdir()], ["history.json"])  # no temp files left
            path.write_text("{broken", encoding="utf-8")
            with mock.patch.object(server, "_log"):
                self.assertEqual(server.load_history(path), [])
            path.write_text(json.dumps([{"room": "Ok"}, {"nope": 1}, "junk"]), encoding="utf-8")
            loaded = server.load_history(path)
            self.assertEqual([e["room"] for e in loaded], ["Ok"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_history_path_env(self):
        with mock.patch.dict(os.environ, {"DECODASH_HOME": "/tmp/somewhere-else"}):
            self.assertEqual(server.current_history_path(), Path("/tmp/somewhere-else/history.json"))
        self.assertIsInstance(server.HISTORY_PATH, Path)
        self.assertEqual(server.HISTORY_PATH.name, "history.json")

    def test_json_safe(self):
        data = server._json_bytes({"a": float("nan"), "b": [float("inf"), 1.5], "c": (1, 2)})
        self.assertEqual(json.loads(data), {"a": None, "b": [None, 1.5], "c": [1, 2]})


class DemoDataTests(unittest.TestCase):
    def test_demo_snapshot(self):
        snap = demo_data.build_demo_snapshot()
        self.assertIs(snap["demo"], True)
        for key in ("generated_at", "settings", "deco", "deco_error", "link", "latency", "speed", "dns", "history"):
            self.assertIn(key, snap)
        deco = snap["deco"]
        names = [n["name"] for n in deco["nodes"]]
        self.assertEqual(names, ["Living Room", "Upstairs Bedroom", "Office"])
        self.assertEqual(deco["nodes"][0]["role"], "main")
        up = deco["nodes"][1]
        self.assertEqual((up["backhaul"], up["signal_dbm"]["band6"], up["rx_rate_mbps"]["band6"]),
                         ("wireless", -71, 860.0))
        self.assertEqual(deco["nodes"][2]["backhaul"], "wired")
        self.assertTrue(17 <= len(deco["clients"]) <= 20)
        self.assertEqual(sum(n["client_count"] for n in deco["nodes"]), len(deco["clients"]))
        bands = {c["band"] for c in deco["clients"]}
        self.assertTrue({"band2_4", "band5", "band6", "wired"} <= bands)
        wifi = deco["wifi"]
        self.assertEqual(wifi["bands"]["band6"]["width_mhz"], 320)
        self.assertEqual(wifi["bands"]["band5"]["width_mhz"], 160)
        self.assertEqual(wifi["bands"]["band2_4"]["channel_width"], "HT40")
        self.assertIs(wifi["mlo_enabled"], False)
        self.assertIs(wifi["iot_enabled"], True)
        self.assertTrue(deco["wan"]["double_nat"])
        self.assertEqual(deco["wan"]["wan_ip"], "192.168.1.20")
        link = snap["link"]
        self.assertEqual((link["os"], link["band"], link["width_mhz"], link["phy"], link["rssi_dbm"]),
                         ("macos", "6GHz", 160, "802.11be", -63))
        speed = snap["speed"]
        self.assertEqual((speed["down_mbps"], speed["up_mbps"], speed["bufferbloat_ms"],
                          speed["bufferbloat_grade"]), (412.0, 38.0, 140.0, "C"))
        self.assertEqual((snap["settings"]["plan_down_mbps"], snap["settings"]["plan_up_mbps"]), (1000.0, 50.0))
        self.assertAlmostEqual(snap["dns"]["median_ms"], 34.0)
        rooms = [h["room"] for h in snap["history"]]
        self.assertEqual(rooms, ["Living Room", "Office", "Kitchen", "Upstairs Bedroom"])
        weakest = min(snap["history"], key=lambda h: h["down_mbps"])
        self.assertEqual(weakest["room"], "Upstairs Bedroom")
        self.assertEqual(min(h["rssi_dbm"] for h in snap["history"]), weakest["rssi_dbm"])
        json.dumps(snap)  # plain JSON

    def test_latency_stats_consistent(self):
        lat = demo_data.demo_latency()
        for target in [lat["gateway"]] + lat["internet"]:
            self.assertEqual(len(target["samples_ms"]), 15)
            self.assertLessEqual(target["median_ms"], target["p90_ms"])

    def test_simulations_are_quick_and_offline(self):
        no_sleep = lambda _s: None  # noqa: E731
        calls = []
        speed = demo_data.simulate_speed("Kitchen", progress_cb=lambda f, m: calls.append(f), sleep=no_sleep)
        self.assertTrue(calls and calls[-1] == 1.0)
        self.assertGreater(speed["down_mbps"], 0)
        self.assertIn(speed["bufferbloat_grade"], ("A+", "A", "B", "C", "D", "F"))
        link = demo_data.simulate_link("Garden shed", sleep=no_sleep)
        self.assertLess(link["rssi_dbm"], -60)
        self.assertEqual(demo_data.simulate_dns(sleep=no_sleep)["error"], None)
        self.assertEqual(len(demo_data.simulate_deco(sleep=no_sleep)["nodes"]), 3)
        self.assertGreater(demo_data.room_profile("Living Room")["down_mbps"],
                           demo_data.room_profile("Upstairs Bedroom")["down_mbps"])


class FileTests(unittest.TestCase):
    def test_web_files_have_no_external_resources(self):
        for name in ("index.html", "app.js", "style.css"):
            text = (WEB / name).read_text("utf-8")
            for bad in ("https://", "//cdn", "@import", "fonts.googleapis", "<script src=\"http"):
                self.assertNotIn(bad, text, "%s contains %s" % (name, bad))
        html = (WEB / "index.html").read_text("utf-8")
        self.assertIn("__DASH_TOKEN__", html)
        self.assertIn('type="password"', html)
        self.assertIn("Read-only: this tool never changes your Deco settings.", html)
        self.assertNotIn("style=", html)
        self.assertNotIn("<script>", html)

    def test_app_js_never_uses_inner_html(self):
        code = (WEB / "app.js").read_text("utf-8")
        lines = [ln for ln in code.splitlines() if not ln.strip().startswith(("*", "/*", "//"))]
        joined = "\n".join(lines)
        for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(bad, joined)

    def test_app_js_syntax(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")
        result = subprocess.run([node, "--check", str(WEB / "app.js")],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))

    def test_run_py_help(self):
        result = subprocess.run([sys.executable, str(ROOT / "run.py"), "--help"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        out = result.stdout.decode("utf-8")
        for flag in ("--port", "--demo", "--no-browser", "--deco-host"):
            self.assertIn(flag, out)

    def test_run_py_rejects_bad_host(self):
        result = subprocess.run([sys.executable, str(ROOT / "run.py"), "--deco-host", "http://x/y", "--no-browser"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(result.returncode, 2)

    def test_run_py_calls_serve(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("decodash_run_py", str(ROOT / "run.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with mock.patch.object(server, "serve") as fake_serve:
            code = module.main(["--demo", "--no-browser", "--port", "9123"])
        self.assertEqual(code, 0)
        fake_serve.assert_called_once_with(port=9123, demo=True, open_browser=False, deco_host="192.168.68.1")


# ---------------------------------------------------------------------------
# Adversarial review tests
# ---------------------------------------------------------------------------

# Runs decodash/web/app.js in node against a tiny fake DOM and prints what ended
# up on the page. argv: app.js state.json [action.js]
FAKE_DOM_JS = r"""
"use strict";
const fs = require("fs");
const vm = require("vm");
const appSrc = fs.readFileSync(process.argv[2], "utf8");
const state = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const errors = [];
class FakeText {
  constructor(s) { this.data = s; this.parentNode = null; this.childNodes = []; }
  get textContent() { return this.data; }
}
class FakeEl {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase(); this.childNodes = []; this.attrs = {};
    this.style = {}; this.listeners = {}; this.hidden = false; this.parentNode = null;
    this.className = ""; this.value = ""; this.open = false; this.disabled = false;
  }
  get firstChild() { return this.childNodes[0] || null; }
  appendChild(c) {
    if (c.parentNode) { c.parentNode.removeChild(c); }
    c.parentNode = this; this.childNodes.push(c); return c;
  }
  removeChild(c) {
    const i = this.childNodes.indexOf(c);
    if (i >= 0) { this.childNodes.splice(i, 1); }
    c.parentNode = null; return c;
  }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === "class") { this.className = String(v); } }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  set textContent(v) { this.childNodes = []; this.appendChild(new FakeText(String(v))); }
  get textContent() { return this.childNodes.map(function (c) { return c.textContent; }).join(""); }
  focus() {} click() {}
}
const byId = {};
const document = {
  readyState: "complete", title: "", activeElement: null, body: new FakeEl("body"),
  getElementById(id) { if (!byId[id]) { byId[id] = new FakeEl("div"); } return byId[id]; },
  querySelector(sel) { return sel.indexOf("dash-token") >= 0 ? { getAttribute: function () { return "tok"; } } : null; },
  createElement(t) { return new FakeEl(t); },
  createElementNS(ns, t) { return new FakeEl(t); },
  createTextNode(s) { return new FakeText(s); },
  addEventListener() {}
};
const fetchCalls = [];
function fakeFetch(path, opts) {
  fetchCalls.push({ path: String(path), method: (opts && opts.method) || "GET", body: (opts && opts.body) || null });
  const raw = JSON.stringify(state);
  return Promise.resolve({ ok: true, status: 200, headers: { get: function () { return null; } },
    text: function () { return Promise.resolve(raw); } });
}
const timers = [];
const sandbox = {
  document: document, fetch: fakeFetch, URL: URL, Date: Date, Math: Math, JSON: JSON,
  console: { error: function () { errors.push(Array.prototype.map.call(arguments, String).join(" ")); }, log: function () {} },
  setTimeout: function (f, ms) { timers.push(ms); return timers.length; }, clearTimeout: function () {},
  confirm: function () { return false; }
};
sandbox.window = sandbox;
vm.createContext(sandbox);
try { vm.runInContext(appSrc, sandbox, { filename: "app.js" }); } catch (e) { errors.push("THROW " + e); }
function walk(node, out) {
  if (node instanceof FakeEl) {
    Object.keys(node.attrs).forEach(function (k) { out.attrs.push(k + "=" + node.attrs[k]); });
    node.childNodes.forEach(function (c) { walk(c, out); });
  }
}
function settle(next) { setImmediate(function () { setImmediate(function () { setTimeout(next, 20); }); }); }
settle(function () {
  if (process.argv[4]) {
    // An action to try after the first draw, e.g. submitting a form.
    new Function("byId", "fetchCalls", fs.readFileSync(process.argv[4], "utf8"))(byId, fetchCalls);
  }
  settle(report);
});
function report() {
  const out = { texts: {}, attrs: [], errors: errors, hidden: {}, fetchCalls: fetchCalls,
                polls: timers.filter(function (t) { return t === 1000; }).length };
  Object.keys(byId).forEach(function (id) {
    out.texts[id] = byId[id].textContent;
    out.hidden[id] = !!byId[id].hidden;
    walk(byId[id], out);
  });
  process.stdout.write(JSON.stringify(out));
}
"""

BAD_WORDS = ("undefined", "NaN", "null", "[object Object]", "Infinity", "native code")


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class AppJsRenderTests(unittest.TestCase):
    """Draw the page from crafted /api/state answers, with app.js running in node."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="decodash-js-")
        cls.harness = Path(cls.tmp) / "fakedom.js"
        cls.harness.write_text(FAKE_DOM_JS, encoding="utf-8")
        cls.env = mock.patch.dict(os.environ, {"DECODASH_HOME": cls.tmp})
        cls.env.start()

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def render(self, payload, action=None):
        path = Path(self.tmp) / "state.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        cmd = [shutil.which("node"), str(self.harness), str(WEB / "app.js"), str(path)]
        if action:
            action_path = Path(self.tmp) / "action.js"
            action_path.write_text(action, encoding="utf-8")
            cmd.append(str(action_path))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        out = json.loads(result.stdout.decode("utf-8"))
        self.assertEqual(out["errors"], [], "app.js logged errors while drawing")
        return out

    def assert_clean(self, out):
        texts = {k: v for k, v in out["texts"].items() if k != "raw-json"}
        for word in BAD_WORDS:
            for key, text in texts.items():
                self.assertNotIn(word, text, "%r shows %r: %s" % (key, word, text[:300]))
            for attr in out["attrs"]:
                self.assertNotIn(word, attr)

    @staticmethod
    def demo_payload():
        return server.DashState(demo=True, demo_delay=0).state_payload()

    def test_empty_real_state_has_no_undefined_nan_or_null(self):
        payload = server.DashState(demo=False).state_payload()
        out = self.render(payload)
        self.assert_clean(out)
        self.assertIn("No speed test yet", out["texts"]["internet"])
        self.assertEqual(out["polls"], 0, "no polling while nothing runs")

    def test_demo_state_draws_cleanly(self):
        out = self.render(self.demo_payload())
        self.assert_clean(out)
        self.assertIn("Upstairs Bedroom", out["texts"]["rooms-chart"])
        self.assertFalse(out["hidden"]["demo-banner"])

    def test_score_null_and_every_field_null(self):
        payload = self.demo_payload()
        snap = payload["snapshot"]
        keys = ("wan_ip", "wan_mask", "gateway", "dial_type", "auto_dns", "lan_ip", "lan_mask",
                "double_nat", "cgnat", "ipv6_enabled")
        snap["deco"] = {
            "fetched_at": None,
            "nodes": [{"mac": None, "name": None, "role": "satellite", "backhaul": "wireless",
                       "backhaul_bands": ["band6"], "signal_dbm": {"band6": None}, "signal_bars": None,
                       "rx_rate_mbps": None, "tx_rate_mbps": None, "client_count": None,
                       "online": None, "internet_online": None, "parent_mac": "AA:BB:CC:DD:EE:FF"}],
            "clients": [{"mac": None, "name": None, "ip": None, "online": True, "band": None,
                         "interface": None, "node_mac": None, "down_kbps": None, "up_kbps": None}],
            "wifi": {"bands": {"band2_4": None, "band5": {"enabled": None, "channel": None,
                                                          "channel_width": None, "width_mhz": None,
                                                          "mode": None, "hidden": None}},
                     "guest_enabled": None, "iot_enabled": None, "mlo_enabled": None,
                     "same_ssid_all_bands": None},
            "wan": dict({k: None for k in keys}, dns=[]),
            "performance": {"cpu_pct": None, "mem_pct": None}, "errors": {}, "raw": {},
        }
        snap["link"] = dict({k: None for k in snap["link"]}, type="wifi", os="windows")
        snap["latency"] = {"gateway": None, "internet": [None, {"name": None, "median_ms": None,
                                                                "jitter_ms": None, "loss_pct": 100.0}],
                           "measured_at": None, "error": None}
        snap["speed"] = {k: None for k in snap["speed"]}
        snap["dns"] = {"median_ms": None, "samples": [], "resolvers": [], "measured_at": None, "error": None}
        snap["history"] = [dict({k: None for k in server.ROOM_TEST_KEYS}, room="Hall")]
        snap["settings"] = {"deco_host": None, "plan_down_mbps": None, "plan_up_mbps": None, "room": None}
        payload["analysis"] = {"score": None, "grade": None, "headline": None, "bottleneck": None,
                               "findings": [], "checklist": [], "data_coverage": None}
        payload["link_node_name"] = None
        out = self.render(payload)
        self.assert_clean(out)
        self.assertIn("?", out["texts"]["score-grade"])

    def test_score_null_from_fallback_analysis(self):
        payload = self.demo_payload()
        payload["analysis"] = server._fallback_analysis(payload["snapshot"], "boom")
        out = self.render(payload)
        self.assert_clean(out)
        self.assertEqual(out["texts"]["score-num"], "no score yet")
        self.assertIn("boom", out["texts"]["analysis-error"])

    def test_html_in_network_data_is_shown_as_text(self):
        evil = '<img src=x onerror="alert(1)">'
        payload = self.demo_payload()
        snap = payload["snapshot"]
        snap["deco"]["clients"][0]["name"] = evil
        snap["deco"]["nodes"][1]["name"] = evil
        snap["history"][-1]["room"] = evil
        snap["link"]["ssid"] = evil
        payload["analysis"]["findings"][0]["title"] = evil
        out = self.render(payload)
        for key in ("devices-table", "mesh", "rooms-chart", "rooms-table", "computer", "findings"):
            self.assertIn(evil, out["texts"][key], key)

    def test_rooms_named_like_object_properties_still_show(self):
        payload = self.demo_payload()
        base = payload["snapshot"]["history"][0]
        names = ["Kitchen", "constructor", "__proto__", "Band", "toString", "valueOf"]
        payload["snapshot"]["history"] = [dict(base, room=name, down_mbps=100.0 + i)
                                          for i, name in enumerate(names)]
        out = self.render(payload)
        chart = out["texts"]["rooms-chart"]
        for name in names:
            self.assertIn(name, chart, "room %r is missing from the chart" % name)
        self.assert_clean(out)

    def test_deco_named_like_object_property(self):
        payload = self.demo_payload()
        nodes = payload["snapshot"]["deco"]["nodes"]
        nodes[1]["name"] = "toString"
        nodes[2]["name"] = "constructor"
        for client in payload["snapshot"]["deco"]["clients"]:
            client.pop("node_name", None)
        out = self.render(payload)
        summary = out["texts"]["devices-summary"]
        self.assertIn("toString: %d" % nodes[1]["client_count"], summary)
        self.assertIn("constructor: %d" % nodes[2]["client_count"], summary)
        self.assert_clean(out)

    def test_unreadable_plan_speed_is_not_saved_as_empty(self):
        # Firefox and Safari let you type "500 Mbps" into a number field; the browser then
        # reports value "" with validity.badInput. That must not wipe the saved plan.
        action = """
            byId["plan-down"].value = "";
            byId["plan-down"].validity = { badInput: true };
            byId["plan-up"].value = "50";
            byId["settings-form"].listeners.submit[0]({ preventDefault: function () {} });
        """
        out = self.render(self.demo_payload(), action)
        posts = [c for c in out["fetchCalls"] if c["path"] == "/api/settings"]
        self.assertEqual(posts, [], "the bad value must not be sent as 'no plan'")
        self.assertIn("numbers", out["texts"]["message"])

    def test_plan_speeds_are_sent(self):
        action = """
            byId["plan-down"].value = "500";
            byId["plan-up"].value = "";
            byId["room-name"].value = " Den ";
            byId["settings-form"].listeners.submit[0]({ preventDefault: function () {} });
        """
        out = self.render(self.demo_payload(), action)
        posts = [c for c in out["fetchCalls"] if c["path"] == "/api/settings"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(json.loads(posts[0]["body"]), {"plan_down_mbps": 500, "plan_up_mbps": None, "room": "Den"})

    def test_polls_while_a_job_runs(self):
        payload = self.demo_payload()
        payload["jobs"]["speed"] = {"status": "running", "progress": None, "message": None}
        out = self.render(payload)
        self.assertEqual(out["polls"], 1)
        self.assertIn("Working", out["texts"]["jobs"])
        self.assert_clean(out)


def _css_vars(css: str) -> dict:
    import re
    return dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", css))


def _contrast(fg: str, bg: str) -> float:
    def lum(hexcolor):
        out = []
        for i in (1, 3, 5):
            c = int(hexcolor[i:i + 2], 16) / 255.0
            out.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
        return 0.2126 * out[0] + 0.7152 * out[1] + 0.0722 * out[2]
    a, b = sorted((lum(fg), lum(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


class ReviewTests(unittest.TestCase):
    def test_hint_text_contrast_on_inner_cards(self):
        # --text-3 is used for small text on --card-2 too (tiles, checklist "How:", finding
        # category), so it needs WCAG AA (4.5:1) there, not only on --card.
        colours = _css_vars((WEB / "style.css").read_text("utf-8"))
        for bg in ("card", "card-2"):
            for fg in ("text", "text-2", "text-3"):
                ratio = _contrast(colours[fg], colours[bg])
                self.assertGreaterEqual(ratio, 4.5, "--%s on --%s is only %.2f:1" % (fg, bg, ratio))

    def test_free_text_can_wrap_on_phones(self):
        # Long names without spaces (e.g. LAPTOP_SAMANTHA_WORKSTATION_2025) must not make
        # the page scroll sideways at 360 px.
        import re
        css = (WEB / "style.css").read_text("utf-8")
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        rules = re.findall(r"([^{}]+)\{([^}]*)\}", css)
        wrapping = set()
        for selectors, body in rules:
            if "overflow-wrap: anywhere" in body:
                wrapping.update(s.strip() for s in selectors.split(","))
        for cls in (".finding-title", ".finding-body", ".check-title", ".check-detail", ".check-how",
                    ".chip", ".job-msg", ".tile-name", ".note", ".headline"):
            self.assertIn(cls, wrapping, cls)
        self.assertIn("grid-template-columns: 30px minmax(0, 1fr)", css)

    def test_saving_does_not_chmod_an_existing_folder(self):
        tmp = tempfile.mkdtemp(prefix="decodash-perm-")
        try:
            if os.name == "nt":
                self.skipTest("POSIX permissions only")
            os.chmod(tmp, 0o755)
            server.save_history(Path(tmp) / "history.json", [])
            self.assertEqual(os.stat(tmp).st_mode & 0o777, 0o755,
                             "DECODASH_HOME=/tmp (or $HOME) must not be locked down to 0700")
            new_dir = Path(tmp) / "fresh"
            server.save_history(new_dir / "history.json", [])
            self.assertEqual(os.stat(str(new_dir)).st_mode & 0o777, 0o700)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_clear_history_wins_over_a_slow_earlier_save(self):
        tmp = tempfile.mkdtemp(prefix="decodash-race-")
        try:
            state = server.DashState(demo=False, history_path=Path(tmp) / "history.json")
            state.snapshot["history"] = [server.build_room_test("Kitchen", None, None, None)]
            real_save = server.save_history
            entered = threading.Event()
            release = threading.Event()
            calls = []

            def slow_first_save(path, history):
                calls.append(len(history))
                if len(calls) == 1:
                    entered.set()
                    release.wait(5)
                real_save(path, history)

            with mock.patch.object(server, "save_history", slow_first_save):
                saver = threading.Thread(target=state._save_history)
                saver.start()
                self.assertTrue(entered.wait(5))
                clearer = threading.Thread(target=state.clear_history)
                clearer.start()
                time.sleep(0.2)
                release.set()
                saver.join(5)
                clearer.join(5)
            self.assertEqual(state.snapshot["history"], [])
            self.assertEqual(server.load_history(Path(tmp) / "history.json"), [],
                             "the file must match what the page shows after 'Clear room history'")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_login_failure_message_with_password_inside_is_masked_everywhere(self):
        tmp = tempfile.mkdtemp(prefix="decodash-pw-")
        try:
            with mock.patch.dict(os.environ, {"DECODASH_HOME": tmp}):
                state = server.DashState(demo=False)
                module = fake_deco_module(FakeDecoConnectionError("could not reach S3cret-pw!"))
                with mock.patch.object(server, "_deco_module", lambda: module):
                    with self.assertRaises(server.ApiError) as ctx:
                        state.login("192.168.68.1", "S3cret-pw!")
                self.assertEqual(ctx.exception.status, 502)
                payload = json.dumps(state.state_payload())
                self.assertNotIn("S3cret-pw!", payload)
                self.assertNotIn("S3cret-pw!", ctx.exception.message)
                for name in os.listdir(tmp):
                    self.assertNotIn("S3cret-pw!", (Path(tmp) / name).read_text("utf-8"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_host_header_variants(self):
        srv = server.make_server(0, demo=True, demo_delay=0)
        thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            def status_for(host):
                conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
                try:
                    conn.putrequest("GET", "/api/state", skip_host=True)
                    if host is not None:
                        conn.putheader("Host", host)
                    conn.putheader("X-Dash-Token", srv.token)
                    conn.endheaders()
                    return conn.getresponse().status
                finally:
                    conn.close()

            self.assertEqual(status_for("127.0.0.1:%d" % srv.port), 200)
            self.assertEqual(status_for("LOCALHOST:%d" % srv.port), 200)
            for bad in (None, "", "127.0.0.1", "localhost", "127.0.0.1:%d.evil.example" % srv.port,
                        "evil.example:%d" % srv.port, "127.0.0.2:%d" % srv.port,
                        "[::1]:%d" % srv.port, "0.0.0.0:%d" % srv.port):
                self.assertEqual(status_for(bad), 403, bad)
        finally:
            srv.shutdown()
            srv.server_close()
            thread.join(5)

    def test_token_must_match_exactly(self):
        srv = server.make_server(0, demo=True, demo_delay=0)
        thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            for token in ("", srv.token[:-1], srv.token + "x", srv.token.upper() if srv.token.upper() != srv.token
                          else srv.token.lower(), " " + srv.token + "x"):
                conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
                try:
                    conn.request("GET", "/api/export", headers={"X-Dash-Token": token})
                    resp = conn.getresponse()
                    body = resp.read()
                    self.assertEqual(resp.status, 403, token)
                    self.assertNotIn(b"snapshot", body)
                finally:
                    conn.close()
        finally:
            srv.shutdown()
            srv.server_close()
            thread.join(5)

    def test_more_static_traversal_attempts(self):
        srv = server.make_server(0, demo=True, demo_delay=0)
        thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            for path in ("/static/%2e%2e%2fserver.py", "/static/..%5cserver.py", "/static/%5c..%5cserver.py",
                         "/static/app.js%00.css", "/static//etc/passwd", "/static/../../decodash/server.py",
                         "/static/%252e%252e/server.py", "//static/../server.py", "/static/index.html/.."):
                conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
                try:
                    conn.request("GET", path, headers={"Host": "127.0.0.1:%d" % srv.port})
                    resp = conn.getresponse()
                    body = resp.read()
                    self.assertIn(resp.status, (400, 403, 404), path)
                    self.assertNotIn(b"import", body, path)
                    self.assertNotIn(b"root:", body, path)
                finally:
                    conn.close()
        finally:
            srv.shutdown()
            srv.server_close()
            thread.join(5)

    def test_room_test_node_name_on_satellite_band5(self):
        nodes = demo_data.build_demo_deco()["nodes"]
        link = dict(demo_data.demo_link(), bssid="a8:42:a1:3c:61:26", band="5GHz")
        entry = server.build_room_test("Landing", link, None, None, nodes)
        self.assertEqual(entry["node_name"], "Upstairs Bedroom")
        self.assertIsNone(entry["down_mbps"])
        self.assertIsNone(entry["latency_ms"])


if __name__ == "__main__":
    unittest.main()
