"""Tests for decodash.deco_client against tests/mock_deco.py (no real Deco, no internet)."""

from __future__ import annotations

import copy
import datetime
import ipaddress
import json
import os
import socket
import ssl
import sys
import tempfile
import time
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from decodash import deco_client as dc  # noqa: E402
from decodash.deco_client import (  # noqa: E402
    DecoAuthError,
    DecoClient,
    DecoConnectionError,
    DecoError,
    DecoUnsupportedFirmware,
    decode_name,
    normalize_band,
    normalize_clients,
    normalize_mac,
    normalize_nodes,
    normalize_performance,
    normalize_wan,
    normalize_wlan,
    parse_enable,
    redact,
)
from tests.mock_deco import (  # noqa: E402
    BEDROOM_MAC,
    MAIN_MAC,
    OFFICE_MAC,
    WIFI_PASSWORDS,
    MockDeco,
    RedirectServer,
    b64,
)

PASSWORD = "correct horse"

NODE_KEYS = {
    "mac", "name", "model", "hw_version", "fw_version", "ip", "role", "online", "internet_online",
    "parent_mac", "backhaul", "backhaul_bands", "signal_dbm", "signal_bars", "rx_rate_mbps",
    "tx_rate_mbps", "backhaul_speed_mbps", "backhaul_max_mbps", "wired_ports", "client_count",
}
CLIENT_KEYS = {"mac", "name", "ip", "online", "band", "interface", "node_mac", "down_kbps", "up_kbps"}
BAND_CFG_KEYS = {"enabled", "channel", "channel_width", "width_mhz", "mode", "backhaul_channel", "hidden"}
WAN_KEYS = {"wan_ip", "wan_mask", "gateway", "dial_type", "dns", "auto_dns", "lan_ip", "lan_mask",
            "double_nat", "cgnat", "ipv6_enabled"}
RAW_KEYS = {"device_list", "client_list", "wlan", "wan_ipv4", "performance", "ipv6"}
BANDS = ("band2_4", "band5", "band6")


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# Against the mock Deco
# ---------------------------------------------------------------------------


class MockDecoTestCase(unittest.TestCase):
    def setUp(self):
        self.mock = MockDeco(password=PASSWORD)
        self.url = self.mock.start()

    def tearDown(self):
        self.mock.stop()

    def client(self, password=PASSWORD, timeout=5.0, url=None):
        return DecoClient(url or self.url, password, timeout=timeout)

    def assertClean(self):
        self.assertEqual(self.mock.violations, [])
        self.assertEqual(self.mock.protocol_errors, [])


class LoginTests(MockDecoTestCase):
    def test_login_success(self):
        c = self.client()
        self.assertFalse(c.logged_in)
        c.login()
        self.assertTrue(c.logged_in)
        self.assertEqual(self.mock.counters["keys"], 1)
        self.assertEqual(self.mock.counters["auth"], 1)
        self.assertEqual(self.mock.counters["login_ok"], 1)
        self.assertTrue(self.mock.session_active)
        self.assertClean()

    def test_host_without_scheme(self):
        port = self.url.rsplit(":", 1)[1]
        c = DecoClient("127.0.0.1:%s" % port, PASSWORD, timeout=5)
        self.assertEqual(c.base_url, self.url)
        self.assertEqual(c.host, "127.0.0.1")
        c.login()
        self.assertTrue(c.logged_in)

    def test_wrong_password_mentions_tries_left(self):
        c = self.client(password="wrong horse")
        with self.assertRaises(DecoAuthError) as ctx:
            c.login()
        message = str(ctx.exception)
        self.assertIn("tries left", message)
        self.assertRegex(message, r"\b9\b")  # mock starts with 10 tries
        self.assertNotIn("wrong horse", message)
        self.assertFalse(c.logged_in)
        self.assertEqual(self.mock.counters["login_wrong_password"], 1)
        self.assertClean()

    def test_out_of_tries(self):
        self.mock.attempts_allowed = 1
        c = self.client(password="nope")
        with self.assertRaises(DecoAuthError) as ctx:
            c.login()
        self.assertIn("0 tries left", str(ctx.exception))

    def test_fetch_all_with_wrong_password_raises(self):
        with self.assertRaises(DecoAuthError):
            self.client(password="nope").fetch_all()

    def test_403_means_owner_logged_in_elsewhere(self):
        self.mock.login_forbidden = True
        c = self.client()
        with self.assertRaises(DecoAuthError) as ctx:
            c.login()
        message = str(ctx.exception)
        self.assertIn("Deco app", message)
        self.assertIn("logged in", message)
        self.assertIn("403", message)
        self.assertEqual(self.mock.counters["login_forbidden"], 1)

    def test_401_on_keys_is_unsupported_firmware(self):
        self.mock.keys_status = 401
        c = self.client()
        with self.assertRaises(DecoUnsupportedFirmware) as ctx:
            c.login()
        self.assertIsInstance(ctx.exception, DecoError)
        self.assertIn("401", str(ctx.exception))
        self.assertEqual(self.mock.counters["auth"], 0)

    def test_empty_password(self):
        with self.assertRaises(DecoAuthError):
            self.client(password="").login()
        self.assertEqual(self.mock.counters["requests"], 0)

    def test_bad_host(self):
        with self.assertRaises(DecoConnectionError):
            DecoClient("", PASSWORD)
        with self.assertRaises(DecoConnectionError):
            DecoClient("ftp://192.168.68.1", PASSWORD)

    def test_repr_hides_password(self):
        c = self.client()
        self.assertNotIn(PASSWORD, repr(c))


class SessionTests(MockDecoTestCase):
    def test_session_expiry_error_code_relogin(self):
        self.mock.expire_session_after = 2
        data = self.client().fetch_all()
        self.assertEqual(data["errors"], {})
        self.assertEqual(self.mock.counters["expired_sent"], 1)
        self.assertEqual(self.mock.counters["login_ok"], 2)
        self.assertEqual(len(data["nodes"]), 3)
        self.assertClean()

    def test_session_expiry_http_401_and_403(self):
        for status in (401, 403):
            with self.subTest(status=status):
                mock = MockDeco(password=PASSWORD)
                url = mock.start()
                try:
                    mock.expire_session_after = 1
                    mock.expire_mode = status
                    data = DecoClient(url, PASSWORD, timeout=5).fetch_all()
                    self.assertEqual(data["errors"], {})
                    self.assertEqual(mock.counters["expired_sent"], 1)
                    self.assertEqual(mock.counters["login_ok"], 2)
                finally:
                    mock.stop()

    def test_stale_session_is_renewed(self):
        c = self.client()
        c.login()
        self.mock._session = None  # e.g. the Deco rebooted
        data = c.fetch_all()
        self.assertEqual(data["errors"], {})
        self.assertEqual(self.mock.counters["login_ok"], 2)

    def test_relogin_forbidden_stops_hammering(self):
        c = self.client()
        c.login()
        self.mock.expire_session_after = 1
        self.mock.login_forbidden = True
        data = c.fetch_all()
        self.assertEqual(self.mock.counters["login_forbidden"], 1)
        self.assertIn("client_list", data["errors"])
        self.assertIn("Deco app", data["errors"]["client_list"])
        self.assertTrue(data["errors"]["wlan"].startswith("Skipped"))
        self.assertEqual(len(data["nodes"]), 3)  # device_list worked before the expiry

    def test_relogin_failing_for_other_reasons_also_stops(self):
        c = self.client()
        c.login()
        self.mock.expire_session_after = 1
        self.mock.keys_status = 500
        data = c.fetch_all()
        self.assertEqual(self.mock.counters["keys"], 2)  # first login + one retry, no more
        self.assertIn("HTTP 500", data["errors"]["client_list"])
        for key in ("wlan", "wan_ipv4", "performance", "client_list_per_node"):
            self.assertIn(key, data["errors"])
        self.assertTrue(data["errors"]["wlan"].startswith("Skipped"))

    def test_empty_login_answer_is_a_plain_deco_error(self):
        c = self.client()
        real_post = c._post

        def fake_post(stok, path, form, body, cookie):
            if form == "login":
                return 200, None, b'{"data": ""}'
            return real_post(stok, path, form, body, cookie)

        c._post = fake_post
        with self.assertRaises(DecoError) as ctx:
            c.login()
        self.assertNotIsInstance(ctx.exception, dc._SessionExpired)
        self.assertFalse(c.logged_in)


class ConnectionTests(unittest.TestCase):
    def test_refused_port(self):
        c = DecoClient("http://127.0.0.1:%d" % _free_port(), PASSWORD, timeout=2)
        start = time.monotonic()
        with self.assertRaises(DecoConnectionError) as ctx:
            c.login()
        self.assertLess(time.monotonic() - start, 3)
        self.assertIn("Couldn't reach", str(ctx.exception))

    def test_silent_host_times_out(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(5)  # accepts connections but never answers
        try:
            c = DecoClient("127.0.0.1:%d" % sock.getsockname()[1], PASSWORD, timeout=0.6)
            start = time.monotonic()
            with self.assertRaises(DecoConnectionError) as ctx:
                c.fetch_all()
            elapsed = time.monotonic() - start
            self.assertLess(elapsed, 0.6 + 2.0)
            self.assertGreaterEqual(elapsed, 0.5)
            self.assertIn("didn't answer", str(ctx.exception))
        finally:
            sock.close()

    def test_tls_verification_only_skipped_for_private_ip_literals(self):
        for host in ("192.168.68.1", "10.0.0.2", "172.16.5.4", "169.254.10.1", "127.0.0.1",
                     "fe80::1", "fd00::1"):
            with self.subTest(host=host):
                ctx = dc._tls_context_for(host)
                self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
                self.assertFalse(ctx.check_hostname)
        for host in ("deco.local", "tplinkdeco.net", "8.8.8.8", "100.64.0.1", "example.com", None, ""):
            with self.subTest(host=host):
                ctx = dc._tls_context_for(host)
                self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(ctx.check_hostname)

    def test_proxies_from_environment_are_ignored(self):
        old = os.environ.get("http_proxy")
        os.environ["http_proxy"] = "http://127.0.0.1:%d" % _free_port()
        mock = MockDeco(password=PASSWORD)
        url = mock.start()
        try:
            DecoClient(url, PASSWORD, timeout=5).login()
            self.assertEqual(mock.counters["login_ok"], 1)
        finally:
            mock.stop()
            if old is None:
                os.environ.pop("http_proxy", None)
            else:
                os.environ["http_proxy"] = old


def _make_self_signed_cert(directory: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mock-deco")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(directory, "cert.pem")
    key_path = os.path.join(directory, "key.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return cert_path, key_path


class RedirectTests(unittest.TestCase):
    def test_http_to_https_redirect_switches_base_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            try:
                cert, key = _make_self_signed_cert(tmp)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as err:  # cryptography missing, too old or broken
                self.skipTest("cannot make a test certificate: %s" % type(err).__name__)
            mock = MockDeco(password=PASSWORD, tls_certfile=cert, tls_keyfile=key)
            https_url = mock.start()
            redirect = RedirectServer(https_url, status=307)  # urllib won't follow 307 for POST
            http_url = redirect.start()
            try:
                c = DecoClient(http_url, PASSWORD, timeout=5)
                data = c.fetch_all()
                self.assertTrue(c.base_url.startswith("https://127.0.0.1:"))
                self.assertEqual(c.base_url, https_url)
                self.assertEqual(redirect.hits, 1)  # switched for the rest of the session
                self.assertEqual(data["errors"], {})
                self.assertEqual(mock.counters["login_ok"], 1)
                self.assertEqual(mock.violations, [])
                self.assertEqual(mock.protocol_errors, [])
            finally:
                redirect.stop()
                mock.stop()

    def test_redirect_to_another_host_is_refused(self):
        mock = MockDeco(password=PASSWORD)
        url = mock.start()
        redirect = RedirectServer(url.replace("127.0.0.1", "localhost"), status=302)
        try:
            c = DecoClient(redirect.start(), PASSWORD, timeout=3)
            with self.assertRaises(DecoConnectionError) as ctx:
                c.login()
            self.assertIn("different address", str(ctx.exception))
            self.assertEqual(mock.counters["requests"], 0)
        finally:
            redirect.stop()
            mock.stop()


class FetchAllTests(MockDecoTestCase):
    def test_fetch_all_logs_in_and_has_every_spec_key(self):
        data = self.client().fetch_all()
        for key in ("fetched_at", "nodes", "clients", "wifi", "wan", "performance", "errors", "raw"):
            self.assertIn(key, data)
        datetime.datetime.fromisoformat(data["fetched_at"])
        self.assertEqual(data["errors"], {})
        self.assertTrue(RAW_KEYS.issubset(data["raw"]))
        self.assertEqual(len(data["nodes"]), 3)
        for node in data["nodes"]:
            self.assertTrue(NODE_KEYS.issubset(node), NODE_KEYS - set(node))
            for group in ("signal_dbm", "signal_bars", "rx_rate_mbps", "tx_rate_mbps"):
                self.assertEqual(set(BANDS), set(node[group]))
        self.assertEqual(len(data["clients"]), 9)
        for client in data["clients"]:
            self.assertTrue(CLIENT_KEYS.issubset(client), CLIENT_KEYS - set(client))
            self.assertIn(client["band"], ("band2_4", "band5", "band6", "wired", "unknown"))
        self.assertEqual(set(BANDS), set(data["wifi"]["bands"]) & set(BANDS))
        for key in ("guest_enabled", "iot_enabled", "mlo_enabled", "same_ssid_all_bands"):
            self.assertIn(key, data["wifi"])
        for cfg in data["wifi"]["bands"].values():
            self.assertTrue(BAND_CFG_KEYS.issubset(cfg))
        self.assertTrue(WAN_KEYS.issubset(data["wan"]))
        self.assertEqual(set(data["performance"]), {"cpu_pct", "mem_pct"})
        json.dumps(data)  # must be JSON-serialisable
        self.assertClean()

    def test_fetch_all_values_for_the_be65_mesh(self):
        data = self.client().fetch_all()
        main, bedroom, office = data["nodes"]
        self.assertEqual((main["name"], main["role"], main["backhaul"]), ("Living Room", "main", "n/a"))
        self.assertEqual(main["model"], "BE65")
        self.assertEqual(main["mac"], "A8:42:A1:3C:5E:10")
        self.assertEqual(bedroom["name"], "Bedroom")
        self.assertEqual(bedroom["backhaul"], "wireless")
        self.assertEqual(bedroom["backhaul_bands"], ["band6", "band5"])
        self.assertEqual(bedroom["signal_dbm"], {"band2_4": None, "band5": -58, "band6": -63})
        self.assertEqual(bedroom["rx_rate_mbps"]["band6"], 2161)
        self.assertEqual(bedroom["parent_mac"], main["mac"])
        self.assertEqual(office["name"], "Office")
        self.assertEqual(office["backhaul"], "wired")
        self.assertEqual(office["backhaul_speed_mbps"], 2500)
        self.assertEqual([n["client_count"] for n in data["nodes"]], [3, 3, 2])

        by_name = {c["name"]: c for c in data["clients"]}
        self.assertEqual(by_name["Maya's iPhone 15"]["band"], "band6")
        self.assertEqual(by_name["Maya's iPhone 15"]["node_mac"], bedroom["mac"])
        self.assertEqual(by_name["Maya's iPhone 15"]["down_kbps"], 10000.0)
        self.assertEqual(by_name["PS5"]["band"], "wired")
        self.assertEqual(by_name["PS5"]["node_mac"], office["mac"])
        self.assertEqual(by_name["Echo Dot"]["interface"], "iot")
        self.assertEqual(by_name["Sam's Pixel 8"]["interface"], "guest")
        self.assertEqual(by_name["Kindle"]["band"], "band2_4")  # plain (not base64) name kept
        self.assertFalse(by_name["Old iPad"]["online"])

        wifi = data["wifi"]
        self.assertEqual(wifi["bands"]["band5"]["width_mhz"], 160)
        self.assertEqual(wifi["bands"]["band6"]["width_mhz"], 320)
        self.assertEqual(wifi["bands"]["band6"]["channel_width"], "EHT320")
        self.assertTrue(wifi["guest_enabled"])
        self.assertTrue(wifi["iot_enabled"])
        self.assertTrue(wifi["mlo_enabled"])
        self.assertTrue(wifi["same_ssid_all_bands"])

        wan = data["wan"]
        self.assertTrue(wan["double_nat"])
        self.assertFalse(wan["cgnat"])
        self.assertEqual(wan["dns"], ["192.168.1.1"])
        self.assertIsNone(wan["ipv6_enabled"])
        self.assertEqual(data["performance"], {"cpu_pct": 27.0, "mem_pct": 61.0})

    def test_per_node_client_lists_use_device_list_macs_exactly(self):
        self.client().fetch_all()
        per_node = [r["params"]["device_mac"] for r in self.mock.requests
                    if r["form"] == "client_list" and r["params"]["device_mac"] != "default"]
        self.assertEqual(sorted(per_node), sorted([MAIN_MAC, BEDROOM_MAC, OFFICE_MAC]))
        self.assertEqual(self.mock.counters["client_list_unknown_mac"], 0)

    def test_no_secrets_anywhere_in_output(self):
        c = self.client()
        data = c.fetch_all()
        text = json.dumps(data)
        self.assertNotIn(PASSWORD, text)
        for pw in WIFI_PASSWORDS:
            self.assertNotIn(pw, text)
            self.assertNotIn(b64(pw), text)
        self.assertNotIn(self.mock.current_stok, text)
        self.assertNotIn(self.mock.current_sysauth, text)
        self.assertEqual(data["raw"]["wlan"]["band2_4"]["host"]["password"], "***")
        self.assertEqual(data["raw"]["wlan"]["iot"]["host"]["password"], "***")
        self.assertIn("***", text)

    def test_violations_stay_empty_including_logout(self):
        c = self.client()
        c.fetch_all()
        c.logout()
        self.assertFalse(c.logged_in)
        self.assertEqual(self.mock.counters["logout"], 1)
        self.assertFalse(self.mock.session_active)
        ops = {r["operation"] for r in self.mock.requests}
        self.assertTrue(ops.issubset({"read", "login", "logout"}), ops)
        self.assertClean()

    def test_write_operations_are_blocked_before_sending(self):
        c = self.client()
        c.login()
        before = len(self.mock.requests)
        for op in ("write", "reboot", "remove"):
            with self.subTest(op=op):
                with self.assertRaises(DecoError):
                    c._call("admin/wireless", "wlan", {"operation": op, "params": {}})
        self.assertEqual(len(self.mock.requests), before)
        self.assertClean()

    def test_one_endpoint_failing_does_not_stop_the_others(self):
        self.mock.fail_forms = {"wlan": 500}
        data = self.client().fetch_all()
        self.assertEqual(set(data["errors"]), {"wlan"})
        self.assertIn("Wi-Fi settings", data["errors"]["wlan"])
        self.assertEqual(data["wifi"]["bands"], {"band2_4": None, "band5": None, "band6": None})
        self.assertIsNone(data["raw"]["wlan"])
        self.assertEqual(len(data["nodes"]), 3)
        self.assertEqual(len(data["clients"]), 9)
        self.assertTrue(data["wan"]["double_nat"])

    def test_per_node_failure_leaves_node_mac_none(self):
        self.mock.fail_forms = {"client_list:per_node": 500}
        data = self.client().fetch_all()
        self.assertIn("client_list_per_node", data["errors"])
        self.assertEqual(len(data["clients"]), 9)
        self.assertTrue(all(c["node_mac"] is None for c in data["clients"]))
        self.assertEqual([n["client_count"] for n in data["nodes"]], [0, 0, 0])

    def test_main_client_list_failing_uses_per_node_lists(self):
        self.mock.fail_forms = {"client_list:default": 500}
        data = self.client().fetch_all()
        self.assertEqual(set(data["errors"]), {"client_list"})
        self.assertEqual(len(data["clients"]), 9)
        self.assertTrue(all(c["node_mac"] for c in data["clients"]))

    def test_optional_ipv6_errors_are_ignored(self):
        data = self.client().fetch_all()  # default fixtures have no wan_ipv6
        self.assertNotIn("ipv6", data["errors"])
        self.assertIsNone(data["raw"]["ipv6"])

    def test_ipv6_read_when_present(self):
        self.mock.fixtures["wan_ipv6"] = {"wan": {"enable": "on", "dial_type": "dynamic_ip"}}
        data = self.client().fetch_all()
        self.assertTrue(data["wan"]["ipv6_enabled"])

    def test_slow_endpoint_times_out_but_others_work(self):
        self.mock.delay_forms = {"performance": 1.5}
        data = self.client(timeout=0.5).fetch_all()
        self.assertIn("performance", data["errors"])
        self.assertEqual(data["performance"], {"cpu_pct": None, "mem_pct": None})
        self.assertEqual(len(data["nodes"]), 3)

    def test_logout_never_raises(self):
        c = self.client(timeout=1)
        c.logout()  # not logged in: no-op
        c.login()
        self.mock.stop()
        c.logout()  # Deco gone: still no exception
        self.assertFalse(c.logged_in)


# ---------------------------------------------------------------------------
# Pure normaliser tests (no network)
# ---------------------------------------------------------------------------

X50_DEVICE_LIST = json.loads("""[
 {"role":"slave","nickname":"Kids","device_ip":"192.168.71.250","mac":"F0-09-0D-FA-29-84",
  "device_model":"X50","hardware_ver":"1.0","software_ver":"1.8.0 Build 25102213 Rel. 43970",
  "inet_status":"online","group_status":"connected","previous":"F0-09-0D-FA-29-7C","port_count":3,
  "signal_strength":{"band5":-50,"band2_4":-37},
  "rx_rate_list":{"band5":960,"band2_4":412},"tx_rate_list":{"band5":1297,"band2_4":258}},
 {"role":"master","nickname":"Living Room","device_ip":"192.168.68.1","mac":"F0-09-0D-FA-29-7C",
  "inet_status":"online","group_status":"connected","previous":"","signal_level":{"band5":"0","band2_4":"0"}}
]""")

OLD_SATELLITE = {
    "role": "slave", "nickname": "kitchen", "custom_nickname": b64("Kitchen Deco"),
    "connection_type": ["band2_4", "band5"], "signal_level": {"band2_4": "3", "band5": "2"},
    "backhual_speed": "866", "backhual_max_speed": 1300, "bssid_2g": "ab:e4:7e:33:04:a6",
    "bssid_5g": "8e:79:41:b5:66:df", "bssid_sta_2g": "be:e1:db:01:4b:ab",
    "bssid_sta_5g": "91:4d:4e:b4:8a:fd", "previous": "2d:a9:80:57:f9:05", "mac": "2b:19:b1:0a:90:d4",
    "group_status": "connected", "inet_status": "online", "device_model": "M4R", "hardware_ver": "5",
    "software_ver": "1.5.49", "device_ip": "192.168.68.250",
}


class NodeNormaliserTests(unittest.TestCase):
    def test_new_style_dbm_satellite_and_main_first(self):
        nodes = normalize_nodes(X50_DEVICE_LIST)
        self.assertEqual([n["role"] for n in nodes], ["main", "satellite"])
        main, kids = nodes
        self.assertEqual(kids["name"], "Kids")
        self.assertEqual(kids["mac"], "F0:09:0D:FA:29:84")
        self.assertEqual(kids["model"], "X50")
        self.assertEqual(kids["hw_version"], "1.0")
        self.assertEqual(kids["fw_version"], "1.8.0 Build 25102213 Rel. 43970")
        self.assertEqual(kids["ip"], "192.168.71.250")
        self.assertTrue(kids["online"])
        self.assertTrue(kids["internet_online"])
        self.assertEqual(kids["parent_mac"], "F0:09:0D:FA:29:7C")
        self.assertEqual(kids["backhaul"], "wireless")
        self.assertEqual(kids["backhaul_bands"], ["band5", "band2_4"])
        self.assertEqual(kids["signal_dbm"], {"band2_4": -37, "band5": -50, "band6": None})
        self.assertEqual(kids["signal_bars"], {"band2_4": None, "band5": None, "band6": None})
        self.assertEqual(kids["rx_rate_mbps"], {"band2_4": 412, "band5": 960, "band6": None})
        self.assertEqual(kids["tx_rate_mbps"], {"band2_4": 258, "band5": 1297, "band6": None})
        self.assertEqual(kids["wired_ports"], 3)
        self.assertEqual(kids["client_count"], 0)

    def test_main_gives_backhaul_na(self):
        main = normalize_nodes(X50_DEVICE_LIST)[0]
        self.assertEqual(main["name"], "Living Room")
        self.assertEqual(main["backhaul"], "n/a")
        self.assertEqual(main["backhaul_bands"], [])
        self.assertIsNone(main["parent_mac"])
        self.assertEqual(main["signal_bars"], {"band2_4": None, "band5": None, "band6": None})
        self.assertIsNone(main["model"])

    def test_old_style_bars_and_connection_type_list(self):
        node = normalize_nodes([OLD_SATELLITE])[0]
        self.assertEqual(node["role"], "satellite")
        self.assertEqual(node["name"], "Kitchen Deco")  # base64 custom_nickname decoded
        self.assertEqual(node["backhaul"], "wireless")
        self.assertEqual(node["backhaul_bands"], ["band5", "band2_4"])
        self.assertEqual(node["signal_bars"], {"band2_4": 3, "band5": 2, "band6": None})
        self.assertEqual(node["backhaul_speed_mbps"], 866.0)
        self.assertEqual(node["backhaul_max_mbps"], 1300.0)
        self.assertEqual(node["parent_mac"], "2D:A9:80:57:F9:05")
        self.assertEqual(node["mac"], "2B:19:B1:0A:90:D4")

    def test_wired_satellite(self):
        for conn in (["wired"], ["ethernet"], "wired", ["WIRED"]):
            with self.subTest(conn=conn):
                item = {"role": "slave", "nickname": "office", "mac": "AA-BB-CC-DD-EE-01",
                        "connection_type": conn, "signal_level": {"band2_4": "0", "band5": "0"},
                        "previous": "AA-BB-CC-DD-EE-00"}
                node = normalize_nodes([item])[0]
                self.assertEqual(node["backhaul"], "wired")
                self.assertEqual(node["name"], "Office")
                self.assertEqual(node["signal_bars"], {"band2_4": None, "band5": None, "band6": None})

    def test_satellite_with_no_backhaul_info_is_unknown(self):
        node = normalize_nodes([{"role": "slave", "mac": "AA:BB:CC:DD:EE:02"}])[0]
        self.assertEqual(node["backhaul"], "unknown")
        self.assertEqual(node["backhaul_bands"], [])
        self.assertEqual(node["name"], "AA:BB:CC:DD:EE:02")

    def test_band5_1_and_band6_signal_keys(self):
        item = {"role": "slave", "mac": "AA:BB:CC:DD:EE:03",
                "signal_strength": {"band5_1": "-61", "band6": -70, "band2_4": 0}}
        node = normalize_nodes([item])[0]
        self.assertEqual(node["signal_dbm"], {"band2_4": None, "band5": -61, "band6": -70})
        self.assertEqual(node["backhaul_bands"], ["band6", "band5"])

    def test_client_count_from_clients(self):
        clients = [
            {"mac": "1", "online": True, "node_mac": "F0:09:0D:FA:29:84"},
            {"mac": "2", "online": True, "node_mac": "F0:09:0D:FA:29:84"},
            {"mac": "3", "online": False, "node_mac": "F0:09:0D:FA:29:84"},
            {"mac": "4", "online": True, "node_mac": "F0:09:0D:FA:29:7C"},
            {"mac": "5", "online": True, "node_mac": None},
        ]
        main, kids = normalize_nodes(X50_DEVICE_LIST, clients)
        self.assertEqual(kids["client_count"], 2)
        self.assertEqual(main["client_count"], 1)

    def test_single_unit_without_role_is_main(self):
        node = normalize_nodes([{"mac": "AA:BB:CC:DD:EE:04", "nickname": "hall"}])[0]
        self.assertEqual(node["role"], "main")
        self.assertEqual(node["backhaul"], "n/a")
        self.assertEqual(node["name"], "Hall")

    def test_nickname_is_plain_text_and_custom_nickname_wins(self):
        cases = (
            ({"nickname": "living_room"}, "Living Room"),
            ({"nickname": "Kids"}, "Kids"),
            ({"nickname": "TWFpbg=="}, "TWFpbg=="),  # nickname is never base64-decoded
            ({"nickname": "kitchen", "custom_nickname": b64("Mum's Office")}, "Mum's Office"),
            ({"nickname": "kitchen", "custom_nickname": "Garage"}, "Garage"),  # plain custom name
            ({"nickname": "kitchen", "custom_nickname": ""}, "Kitchen"),
        )
        for extra, expected in cases:
            with self.subTest(extra=extra):
                item = dict({"role": "slave", "mac": "AA:BB:CC:DD:EE:05"}, **extra)
                self.assertEqual(normalize_nodes([item])[0]["name"], expected)

    def test_defensive_inputs(self):
        self.assertEqual(normalize_nodes(None), [])
        self.assertEqual(normalize_nodes("garbage"), [])
        self.assertEqual(normalize_nodes({"device_list": X50_DEVICE_LIST})[0]["role"], "main")
        weird = [None, 5, "x", {"mac": 123, "role": ["master"], "signal_strength": [1, 2],
                                "signal_level": "3", "rx_rate_list": None, "port_count": "four",
                                "group_status": 1, "inet_status": None, "previous": 7}]
        nodes = normalize_nodes(weird)
        self.assertEqual(len(nodes), 1)
        self.assertTrue(NODE_KEYS.issubset(nodes[0]))
        self.assertIsNone(nodes[0]["mac"])
        self.assertIsNone(nodes[0]["wired_ports"])
        json.dumps(nodes)


class ClientNormaliserTests(unittest.TestCase):
    SPEC_CLIENT = {"mac": "cf:51:c9:04:e1:02", "up_speed": 17, "down_speed": 3, "wire_type": "wireless",
                   "access_host": "1", "connection_type": "band5", "space_id": "1",
                   "ip": "192.168.68.101", "client_mesh": True, "online": True,
                   "name": "d2lyZWxlc3Mx", "interface": "main"}

    def test_spec_client(self):
        c = normalize_clients([self.SPEC_CLIENT])[0]
        self.assertEqual(c["mac"], "CF:51:C9:04:E1:02")
        self.assertEqual(c["name"], "wireless1")
        self.assertEqual(c["ip"], "192.168.68.101")
        self.assertTrue(c["online"])
        self.assertEqual(c["band"], "band5")
        self.assertEqual(c["interface"], "main")
        self.assertIsNone(c["node_mac"])  # access_host "1" is not a MAC
        self.assertAlmostEqual(c["down_kbps"], 0.024)
        self.assertAlmostEqual(c["up_kbps"], 0.136)

    def test_variants(self):
        items = [
            {"mac": "5f:f8:08:28:af:54", "wire_type": "wired", "connection_type": "wired",
             "name": "d2lyZWQx", "online": True, "ip": "192.168.68.100"},
            {"mac": "", "connection_type": "band2_4", "ip": "UNKNOWN", "name": "d2lyZWxlc3M1",
             "interface": "guest"},
            {"mac": "5f:f8:08:28:af:57", "name": "Kitchen iPad", "online": "0"},
            {"mac": "AA-BB-CC-00-11-22", "connection_type": "band5_2", "access_host": "aa:bb:cc:dd:ee:ff",
             "down_speed": "1000", "up_speed": None, "interface": "iot"},
            {"mac": "AA-BB-CC-00-11-23", "connection_type": "band6", "device_mac": "AA-BB-CC-DD-EE-01"},
            None, "junk", 42,
        ]
        out = normalize_clients(items)
        self.assertEqual(len(out), 5)
        self.assertEqual(out[0]["band"], "wired")
        self.assertEqual(out[0]["name"], "wired1")
        self.assertEqual(out[1]["mac"], "")
        self.assertIsNone(out[1]["ip"])
        self.assertTrue(out[1]["online"])
        self.assertEqual(out[1]["band"], "band2_4")
        self.assertEqual(out[2]["band"], "unknown")
        self.assertEqual(out[2]["name"], "Kitchen iPad")
        self.assertFalse(out[2]["online"])
        self.assertEqual(out[3]["band"], "band5")
        self.assertEqual(out[3]["node_mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(out[3]["down_kbps"], 8.0)
        self.assertEqual(out[3]["up_kbps"], 0.0)
        self.assertEqual(out[4]["band"], "band6")
        self.assertEqual(out[4]["node_mac"], "AA:BB:CC:DD:EE:01")

    def test_defensive(self):
        self.assertEqual(normalize_clients(None), [])
        self.assertEqual(normalize_clients({"client_list": [self.SPEC_CLIENT]})[0]["name"], "wireless1")
        self.assertEqual(normalize_clients("x"), [])


class NameAndMacTests(unittest.TestCase):
    def test_base64_decoding(self):
        self.assertEqual(decode_name("d2lyZWxlc3Mx"), "wireless1")
        self.assertEqual(decode_name(b64("Jason's iPhone")), "Jason's iPhone")
        self.assertEqual(decode_name(b64("Zoë's 📱")), "Zoë's 📱")
        self.assertEqual(decode_name(b64("PS5")), "PS5")

    def test_plain_names_are_kept(self):
        for name in ("Kids", "Room", "Deco", "Main", "Hall", "Desk", "Living Room", "Kindle",
                     "Upstairs", "Basement", "kitchen", "Office-2"):
            with self.subTest(name=name):
                self.assertEqual(decode_name(name), name)

    def test_invalid_base64_or_binary_kept_raw(self):
        self.assertEqual(decode_name("/w=="), "/w==")         # 0xFF is not UTF-8
        self.assertEqual(decode_name("AAECAw=="), "AAECAw==")  # control bytes
        self.assertEqual(decode_name("abc"), "abc")

    def test_non_strings(self):
        self.assertEqual(decode_name(None), "")
        self.assertEqual(decode_name(""), "")
        self.assertEqual(decode_name(12), "12")

    def test_normalize_mac(self):
        for value in ("f0-09-0d-fa-29-84", "F0:09:0D:FA:29:84", "f0090dfa2984", "f009.0dfa.2984",
                      " F0-09-0D-FA-29-84 "):
            with self.subTest(value=value):
                self.assertEqual(normalize_mac(value), "F0:09:0D:FA:29:84")
        for value in (None, "", "1", "default", "00:00:00:00:00:00", "zz:09:0d:fa:29:84", 1234):
            with self.subTest(value=value):
                self.assertIsNone(normalize_mac(value))


class FlagAndBandTests(unittest.TestCase):
    def test_enable_flag_variants(self):
        for value in (True, 1, "1", "on", "enable", "enabled", "true", "ON", " Enabled "):
            with self.subTest(value=value):
                self.assertIs(parse_enable(value), True)
        for value in (False, 0, "0", "off", "disable", "disabled", "false", "OFF"):
            with self.subTest(value=value):
                self.assertIs(parse_enable(value), False)
        for value in (None, "maybe", 2, [], {}):
            with self.subTest(value=value):
                self.assertIsNone(parse_enable(value))

    def test_enable_flags_in_wlan(self):
        for value, expected in ((True, True), (1, True), ("1", True), ("on", True), ("enable", True),
                                ("enabled", True), ("true", True), (False, False), ("0", False),
                                ("off", False), ("disabled", False), ("false", False), ("??", None)):
            with self.subTest(value=value):
                cfg = normalize_wlan({"band2_4": {"host": {"enable": value}}})
                self.assertEqual(cfg["bands"]["band2_4"]["enabled"], expected)

    def test_band_key_normalisation(self):
        self.assertEqual(normalize_band("band5_1"), "band5")
        self.assertEqual(normalize_band("band5_2"), "band5")
        self.assertEqual(normalize_band("band5"), "band5")
        self.assertEqual(normalize_band("band2_4"), "band2_4")
        self.assertEqual(normalize_band("band6"), "band6")
        self.assertIsNone(normalize_band("iot"))
        self.assertIsNone(normalize_band(None))

    def test_wlan_band5_1_and_band5_2(self):
        wlan = {
            "band2_4": {"backhaul": {"channel": 10}, "host": {"channel": 10, "enable": True, "mode": "11ng",
                                                             "channel_width": "HT40", "enable_hide_ssid": False}},
            "band5_1": {"backhaul": {"channel": 44}, "host": {"channel": 44, "enable": True, "mode": "11ac",
                                                             "channel_width": "HT80"}},
            "band5_2": {"backhaul": {"channel": 149}, "host": {"channel": "149", "enable": "1",
                                                              "channel_width": "VHT160"}},
        }
        cfg = normalize_wlan(wlan)
        self.assertEqual(cfg["bands"]["band5"]["channel"], 44)
        self.assertEqual(cfg["bands"]["band5"]["width_mhz"], 80)
        self.assertEqual(cfg["bands"]["band5_2"]["channel"], 149)
        self.assertEqual(cfg["bands"]["band5_2"]["width_mhz"], 160)
        self.assertEqual(cfg["bands"]["band2_4"]["backhaul_channel"], 10)
        self.assertFalse(cfg["bands"]["band2_4"]["hidden"])
        self.assertIsNone(cfg["bands"]["band6"])
        self.assertIsNone(cfg["guest_enabled"])
        self.assertIsNone(cfg["iot_enabled"])
        self.assertIsNone(cfg["mlo_enabled"])
        self.assertIsNone(cfg["same_ssid_all_bands"])

    def test_plain_band5_key_and_widths(self):
        for width, mhz in (("HT20", 20), ("VHT160", 160), ("EHT320", 320), ("auto", None), (None, None),
                           (80, 80)):
            with self.subTest(width=width):
                cfg = normalize_wlan({"band5": {"host": {"channel_width": width, "channel": 0}}})
                self.assertEqual(cfg["bands"]["band5"]["width_mhz"], mhz)
                self.assertIsNone(cfg["bands"]["band5"]["channel"])

    def test_wlan_flags(self):
        wlan = {
            "band2_4": {"host": {"ssid": b64("Home"), "enable": True}, "guest": {"enable": "off"}},
            "band5_1": {"host": {"ssid": b64("Home-5G"), "enable": True}, "guest": {"enable": "enabled"}},
            "iot": {"host": {"enable": "off", "psk": "secret"}},
            "mlo_enable": "0",
        }
        cfg = normalize_wlan(wlan)
        self.assertTrue(cfg["guest_enabled"])
        self.assertFalse(cfg["iot_enabled"])
        self.assertFalse(cfg["mlo_enabled"])
        self.assertFalse(cfg["same_ssid_all_bands"])
        self.assertNotIn("secret", json.dumps(cfg))

    def test_wlan_defensive(self):
        for value in (None, "x", [], {"band2_4": "nope", "band6": {"host": "bad"}}):
            with self.subTest(value=value):
                cfg = normalize_wlan(value)
                self.assertEqual(set(BANDS), set(cfg["bands"]) & set(BANDS))
                json.dumps(cfg)


class WanAndPerformanceTests(unittest.TestCase):
    SPEC_WAN = {"wan": {"ip_info": {"mac": "44:e1:52:8c:40:36", "dns1": "192.168.1.1", "dns2": "0.0.0.0",
                                    "mask": "255.255.255.0", "gateway": "192.168.1.1", "ip": "192.168.1.11"},
                        "dial_type": "dynamic_ip", "enable_auto_dns": True},
                "lan": {"ip_info": {"mac": "44:e1:52:8c:40:37", "mask": "255.255.252.0", "ip": "192.168.68.1"}}}

    def _wan_with_ip(self, ip):
        data = copy.deepcopy(self.SPEC_WAN)
        data["wan"]["ip_info"]["ip"] = ip
        return normalize_wan(data)

    def test_spec_wan_is_double_nat(self):
        wan = normalize_wan(self.SPEC_WAN)
        self.assertEqual(wan["wan_ip"], "192.168.1.11")
        self.assertEqual(wan["wan_mask"], "255.255.255.0")
        self.assertEqual(wan["gateway"], "192.168.1.1")
        self.assertEqual(wan["dial_type"], "dynamic_ip")
        self.assertEqual(wan["dns"], ["192.168.1.1"])
        self.assertTrue(wan["auto_dns"])
        self.assertEqual(wan["lan_ip"], "192.168.68.1")
        self.assertEqual(wan["lan_mask"], "255.255.252.0")
        self.assertTrue(wan["double_nat"])
        self.assertFalse(wan["cgnat"])
        self.assertIsNone(wan["ipv6_enabled"])

    def test_double_nat_ranges(self):
        for ip in ("10.0.0.5", "172.16.0.1", "172.31.255.254", "192.168.0.10"):
            with self.subTest(ip=ip):
                wan = self._wan_with_ip(ip)
                self.assertEqual((wan["double_nat"], wan["cgnat"]), (True, False))

    def test_cgnat(self):
        for ip in ("100.64.0.1", "100.100.12.34", "100.127.255.254"):
            with self.subTest(ip=ip):
                wan = self._wan_with_ip(ip)
                self.assertEqual((wan["double_nat"], wan["cgnat"]), (False, True))

    def test_public_and_unknown(self):
        for ip in ("203.0.113.5", "172.32.0.1", "100.128.0.1", "81.2.69.160"):
            with self.subTest(ip=ip):
                wan = self._wan_with_ip(ip)
                self.assertEqual((wan["double_nat"], wan["cgnat"]), (False, False))
        for ip in ("", "0.0.0.0", None, "not-an-ip"):
            with self.subTest(ip=ip):
                wan = self._wan_with_ip(ip)
                self.assertIsNone(wan["wan_ip"])
                self.assertEqual((wan["double_nat"], wan["cgnat"]), (None, None))

    def test_wan_defensive(self):
        for value in (None, "x", [], {"wan": "bad"}, {"wan": {"ip_info": []}}):
            with self.subTest(value=value):
                wan = normalize_wan(value)
                self.assertTrue(WAN_KEYS.issubset(wan))
                self.assertEqual(wan["dns"], [])
                self.assertIsNone(wan["double_nat"])

    def test_ipv6_detection(self):
        self.assertTrue(normalize_wan(None, {"enable": "on"})["ipv6_enabled"])
        self.assertFalse(normalize_wan(None, {"wan": {"enable": False}})["ipv6_enabled"])
        self.assertTrue(normalize_wan(None, {"wan": {"ip_info": {"ip": "2001:db8::5/64"}}})["ipv6_enabled"])
        self.assertIsNone(normalize_wan(None, {})["ipv6_enabled"])
        self.assertIsNone(normalize_wan(None, "junk")["ipv6_enabled"])

    def test_performance(self):
        self.assertEqual(normalize_performance({"mem_usage": 0.43, "cpu_usage": 0.1}),
                         {"cpu_pct": 10.0, "mem_pct": 43.0})
        self.assertEqual(normalize_performance({"mem_usage": "0.5", "cpu_usage": "1"}),
                         {"cpu_pct": 100.0, "mem_pct": 50.0})
        self.assertEqual(normalize_performance({"cpu_usage": 37}), {"cpu_pct": 37.0, "mem_pct": None})
        for value in (None, "x", {"cpu_usage": "high", "mem_usage": -1}, {"cpu_usage": True}):
            with self.subTest(value=value):
                self.assertEqual(normalize_performance(value), {"cpu_pct": None, "mem_pct": None})


class RedactTests(unittest.TestCase):
    def test_redacts_secret_keys_deeply(self):
        data = {
            "band2_4": {"host": {"ssid": "SG9tZQ==", "password": "c2VjcmV0", "channel": 6}},
            "list": [{"Wifi_Passwd": "a"}, {"psk": "b"}, {"wpa_key": "c"}, {"WPA3_mode": "d"}],
            "client_secret": "e", "token": "f", "stok": "g", "sysauth": "h", "passphrase": "i",
            "key": ["n", "e"], "api_key": "j", "monkey": "keep", "keys": "keep2", "wps_pin": "1234",
            "nested": ({"PSK_Value": "k"},),
            "plain": "keep3",
        }
        original = copy.deepcopy(data)
        out = redact(data)
        self.assertEqual(data, original)  # input untouched
        self.assertEqual(out["band2_4"]["host"]["password"], "***")
        self.assertEqual(out["band2_4"]["host"]["ssid"], "SG9tZQ==")
        self.assertEqual(out["band2_4"]["host"]["channel"], 6)
        self.assertEqual([list(d.values())[0] for d in out["list"]], ["***"] * 4)
        for key in ("client_secret", "token", "stok", "sysauth", "passphrase", "key", "api_key", "wps_pin"):
            self.assertEqual(out[key], "***", key)
        self.assertEqual(out["monkey"], "keep")
        self.assertEqual(out["keys"], "keep2")
        self.assertEqual(out["plain"], "keep3")
        self.assertEqual(out["nested"][0]["PSK_Value"], "***")
        text = json.dumps(out)
        for secret in ("c2VjcmV0", '"a"', '"1234"'):
            self.assertNotIn(secret, text)

    def test_deep_copy(self):
        inner = {"x": [1, 2]}
        out = redact({"inner": inner})
        out["inner"]["x"].append(3)
        self.assertEqual(inner["x"], [1, 2])

    def test_scalars(self):
        self.assertEqual(redact("text"), "text")
        self.assertIsNone(redact(None))
        self.assertEqual(redact([1, "a"]), [1, "a"])

    def test_secret_looking_key_variants(self):
        # SPEC: "... wpa_key and anything that looks like them".
        secret_keys = ("wifiKey", "authKey", "WPAKey", "wep_key1", "wep_key4", "wifi_pass", "x-api-key",
                       "private-key", "privKey", "apiKey", "share.key", "guest_pass", "adminPw", "pinCode",
                       "Cookie", "session_cookie")
        out = redact({k: "s3cret-%d" % i for i, k in enumerate(secret_keys)})
        for key in secret_keys:
            self.assertEqual(out[key], "***", key)
        keep = ("monkey", "keys", "keyboard", "ssid", "bssid_5g", "passive_scan", "pinned", "ping_ms",
                "hotkey", "turnkey", "enable_hide_ssid", "channel_width", "space_id", "access_host")
        out = redact({k: "v" for k in keep})
        for key in keep:
            self.assertEqual(out[key], "v", key)

    def test_nested_lists_and_tuples(self):
        data = [[{"password": "a"}], ({"psk": "b"},), {"x": [[{"y": [{"wpa_key": "c"}]}]]}]
        text = json.dumps(redact(data))
        for secret in ('"a"', '"b"', '"c"'):
            self.assertNotIn(secret, text)


# ---------------------------------------------------------------------------
# Adversarial review tests
# ---------------------------------------------------------------------------


def _load_cryptography():
    try:
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        return {"padding": padding, "rsa": rsa, "sym_padding": sym_padding, "Cipher": Cipher,
                "algorithms": algorithms, "modes": modes}
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:  # missing or broken install (pyo3 PanicException)
        return None


_CRYPTOGRAPHY = _load_cryptography()


@unittest.skipUnless(_CRYPTOGRAPHY, "cryptography is not usable here")
class ReferenceEncodingTests(unittest.TestCase):
    """Byte-for-byte comparison with the hadeco reference ``_encode_payload``."""

    def _reference_encode(self, aes_key, aes_iv, seq, password, payload):
        # Transcribed from hadeco api.py: _encode_data / _encode_sign / _encode_payload.
        import base64
        import hashlib
        from urllib.parse import quote_plus
        c = _CRYPTOGRAPHY
        padder = c["sym_padding"].PKCS7(c["algorithms"].AES.block_size).padder()
        plain = json.dumps(payload, separators=(",", ":")).encode()
        padded = padder.update(plain) + padder.finalize()
        enc = c["Cipher"](c["algorithms"].AES(str(aes_key).encode()), c["modes"].CBC(str(aes_iv).encode())).encryptor()
        data = base64.b64encode(enc.update(padded) + enc.finalize()).decode()
        auth_hash = hashlib.md5(("admin" + password).encode()).digest().hex()
        sign_text = "k=%s&i=%s&h=%s&s=%d" % (aes_key, aes_iv, auth_hash, seq + len(data))
        return data, quote_plus(data), sign_text

    def test_body_matches_reference(self):
        c = _CRYPTOGRAPHY
        key = c["rsa"].generate_private_key(public_exponent=65537, key_size=1024)
        pub = key.public_key().public_numbers()
        client = DecoClient("192.168.68.1", PASSWORD)
        client._sign_n, client._sign_e = pub.n, pub.e
        client._seq = 987654321
        k = (pub.n.bit_length() + 7) // 8
        payloads = ({"operation": "read", "params": {"device_mac": "default"}},
                    {"operation": "read"},
                    {"params": {"password": "ab" * 128}, "operation": "login"},
                    {"operation": "read", "params": {"device_mac": "A8-42-A1-3C-5E-10"}})
        for i, payload in enumerate(payloads * 3):
            with self.subTest(i=i):
                client._aes_key = dc.crypto.random_16_digit()
                client._aes_iv = dc.crypto.random_16_digit()
                body = client._encode_payload(payload)
                raw_data, encoded_data, sign_text = self._reference_encode(
                    client._aes_key, client._aes_iv, client._seq, PASSWORD, payload)
                self.assertTrue(body.startswith("sign="))
                sign_hex, data_part = body[len("sign="):].split("&data=", 1)
                self.assertEqual(data_part, encoded_data)   # quote_plus'd, byte for byte
                self.assertEqual(len(sign_hex) % (2 * k), 0)
                recovered = b"".join(
                    key.decrypt(bytes.fromhex(sign_hex[j:j + 2 * k]), c["padding"].PKCS1v15())
                    for j in range(0, len(sign_hex), 2 * k))
                self.assertEqual(recovered.decode(), sign_text)  # s = seq + len(raw base64)
                if "+" in raw_data or "/" in raw_data or "=" in raw_data:
                    self.assertNotEqual(len(raw_data), len(encoded_data))


class MockStrictnessTests(MockDecoTestCase):
    """The mock must catch the classic encoding mistakes (so the client tests mean something)."""

    def _broken_client(self, mode):
        test = self

        class Broken(DecoClient):
            def _encode_payload(self, payload):
                import base64 as _b64
                import urllib.parse as _up
                text = json.dumps(payload, separators=(",", ":"))
                enc = dc.crypto.aes_cbc_encrypt(self._aes_key.encode(), self._aes_iv.encode(), text.encode())
                data = _b64.b64encode(enc).decode()
                quoted = _up.quote_plus(data)
                length = len(quoted) if mode == "len_after_urlencode" else len(data)
                h = dc._md5_hex(self._username + self._password)
                sign_text = "k=%s&i=%s&h=%s&s=%d" % (self._aes_key, self._aes_iv, h, self._seq + length)
                sign = dc.crypto.rsa_encrypt_chunked(self._sign_n, self._sign_e, sign_text.encode())
                if mode == "no_zero_pad":
                    width = 2 * dc.crypto.byte_len(self._sign_n)
                    sign = "".join(sign[i:i + width].lstrip("0") or "0" for i in range(0, len(sign), width))
                return "sign=%s&data=%s" % (sign, data if mode == "no_quote_plus" else quoted)

        return Broken(test.url, PASSWORD, timeout=5)

    def test_length_after_urlencoding_is_rejected(self):
        for _ in range(5):  # the URL-encoded length differs unless the base64 has no + / =
            client = self._broken_client("len_after_urlencode")
            try:
                client.login()
            except DecoError:
                break
        else:
            self.fail("mock accepted s computed on the URL-encoded data")
        self.assertTrue(any("bad s" in e for e in self.mock.protocol_errors), self.mock.protocol_errors)

    def test_unpadded_hex_is_rejected(self):
        for _ in range(80):  # a block only loses a leading zero ~1 time in 16
            client = self._broken_client("no_zero_pad")
            try:
                client.login()
            except DecoError:
                break
        else:
            self.skipTest("never produced a short hex block")
        self.assertTrue(self.mock.protocol_errors)

    def test_missing_quote_plus_is_rejected(self):
        # Build a fully valid body whose base64 has a '+', then send it once
        # URL-encoded (must pass) and once raw (a real Deco reads '+' as a space).
        import base64 as _b64
        import urllib.parse as _up
        mock = self.mock
        for _ in range(200):
            key, iv = dc.crypto.random_16_digit(), dc.crypto.random_16_digit()
            enc = dc.crypto.aes_cbc_encrypt(key.encode(), iv.encode(), b'{"operation":"read"}')
            data = _b64.b64encode(enc).decode()
            if "+" in data:
                break
        else:
            self.skipTest("no '+' in 200 random ciphertexts")
        h = dc._md5_hex("admin" + PASSWORD)
        sign_text = "k=%s&i=%s&h=%s&s=%d" % (key, iv, h, mock.seq + len(data))
        sign = dc.crypto.rsa_encrypt_chunked(mock.sign_key.n, mock.sign_key.e, sign_text.encode())

        def full_check(body):
            fields, data_b64 = mock._parse_signed_body(body)
            mock._check_sign(fields, data_b64)
            return mock._decrypt_payload(fields["k"], fields["i"], data_b64)

        self.assertEqual(full_check("sign=%s&data=%s" % (sign, _up.quote_plus(data))), {"operation": "read"})
        with self.assertRaises(ValueError):
            full_check("sign=%s&data=%s" % (sign, data))


class RedirectEdgeTests(unittest.TestCase):
    def test_every_redirect_code_keeps_post_and_switches_base(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                mock = MockDeco(password=PASSWORD)
                target = mock.start()
                redirect = RedirectServer(target, status=status)
                try:
                    c = DecoClient(redirect.start(), PASSWORD, timeout=5)
                    data = c.fetch_all()
                    self.assertEqual(c.base_url, target)
                    self.assertEqual(redirect.hits, 1)
                    self.assertEqual(data["errors"], {})
                    self.assertEqual(mock.protocol_errors, [])
                    self.assertEqual(mock.violations, [])  # a 303 must not turn into a GET
                finally:
                    redirect.stop()
                    mock.stop()

    def test_downgrade_loop_and_userinfo_redirects(self):
        c = DecoClient("https://192.168.68.1", PASSWORD)
        with self.assertRaises(DecoConnectionError):
            c._follow_redirect("https://192.168.68.1/x", "http://192.168.68.1/x")  # https -> http
        with self.assertRaises(DecoConnectionError):
            c._follow_redirect("https://192.168.68.1/x", "/webpages/index.html")  # same base: loop
        with self.assertRaises(DecoConnectionError):
            c._follow_redirect("https://192.168.68.1/x", None)
        c = DecoClient("http://192.168.68.1", PASSWORD)
        c._follow_redirect("http://192.168.68.1/x", "https://evil:pw@192.168.68.1:8443/x")
        self.assertEqual(c.base_url, "https://192.168.68.1:8443")


class CookieParsingTests(unittest.TestCase):
    def _headers(self, *values):
        import email.message
        msg = email.message.Message()
        for v in values:
            msg["Set-Cookie"] = v
        return msg

    def test_set_cookie_variants(self):
        cases = (
            (("sysauth=abc123; path=/cgi-bin/luci; HttpOnly",), "abc123"),
            (("foo=1; path=/", "sysauth=deadbeef; path=/"), "deadbeef"),
            (("sysauth=; expires=Thu, 01 Jan 1970 00:00:00 GMT", "sysauth=c0ffee; path=/"), "c0ffee"),
            (("other=1, sysauth=f00d; path=/",), "f00d"),
            (("SYSAUTH=ABCDEF",), "ABCDEF"),
        )
        for values, expected in cases:
            with self.subTest(values=values):
                c = DecoClient("192.168.68.1", PASSWORD)
                c._store_cookie(self._headers(*values))
                self.assertEqual(c._cookie, expected)
        c = DecoClient("192.168.68.1", PASSWORD)
        c._store_cookie(self._headers("foo=bar"))
        c._store_cookie(None)
        self.assertIsNone(c._cookie)


class TlsHostTests(unittest.TestCase):
    def test_globally_routable_ipv6_keeps_verification(self):
        # 6to4 (2002::/16) and Teredo (2001::/32) reach the public internet, and on
        # Python 3.9.6 (macOS) ::ffff:8.8.8.8 counts as "private" in ipaddress.
        for host in ("2002:808:808::1", "2001:0:4136:e378::1", "2001::1", "::ffff:8.8.8.8",
                     "::ffff:100.64.0.1", "64:ff9b::808:808", "203.0.113.9", "198.51.100.7", "192.0.0.9"):
            with self.subTest(host=host):
                self.assertEqual(dc._tls_context_for(host).verify_mode, ssl.CERT_REQUIRED)

    def test_mapped_private_ipv4_and_scoped_link_local_skip(self):
        for host in ("::ffff:192.168.68.1", "[fe80::1%en0]", "fe80::1%eth0", "fc00::5", "::1", "127.0.0.2"):
            with self.subTest(host=host):
                self.assertEqual(dc._tls_context_for(host).verify_mode, ssl.CERT_NONE)


class HostParsingTests(unittest.TestCase):
    def test_userinfo_never_kept(self):
        c = DecoClient("http://admin:hunter2pw@192.168.68.1:8080", PASSWORD)
        self.assertEqual(c.base_url, "http://192.168.68.1:8080")
        self.assertNotIn("hunter2pw", repr(c))
        self.assertEqual(c.host, "192.168.68.1")

    def test_bare_ipv6(self):
        c = DecoClient("fe80::1", PASSWORD)
        self.assertEqual(c.host, "fe80::1")
        self.assertEqual(c.base_url, "http://[fe80::1]")
        c = DecoClient("https://[fd00::1]:8443", PASSWORD)
        self.assertEqual((c.host, c.base_url), ("fd00::1", "https://[fd00::1]:8443"))

    def test_bad_port_is_a_connection_error(self):
        with self.assertRaises(DecoConnectionError):
            DecoClient("192.168.68.1:abc", PASSWORD)


class LoginRobustnessTests(MockDecoTestCase):
    def test_unencodable_password_is_a_deco_auth_error(self):
        bad = "pa\ud800ss"
        c = self.client(password=bad)
        with self.assertRaises(DecoAuthError) as ctx:
            c.login()
        err = ctx.exception
        self.assertIsNone(err.__cause__)
        self.assertIsNone(err.__context__)  # no UnicodeEncodeError (holding the password) chained
        self.assertNotIn(bad, str(err))
        self.assertFalse(c.logged_in)
        self.assertEqual(self.mock.counters["requests"], 0)

    def test_tiny_or_garbage_rsa_key_is_a_deco_error(self):
        from tests.mock_deco import RsaKey
        for key in (RsaKey(0xFFFF, 3, 1), RsaKey(0xA, 0xB, 1)):
            with self.subTest(n=key.n):
                self.mock.password_key = key
                with self.assertRaises(DecoError):
                    self.client().login()

    def test_garbage_key_list_shape(self):
        real_post = None
        c = self.client()
        real_post = c._post

        def fake_post(stok, path, form, body, cookie):
            if form == "keys":
                return 200, None, b'{"error_code":0,"result":{"password":"abc"}}'
            return real_post(stok, path, form, body, cookie)

        c._post = fake_post
        with self.assertRaises(DecoError):
            c.login()


class NonFiniteJsonTests(MockDecoTestCase):
    def test_infinity_and_nan_from_the_deco(self):
        # json.loads accepts NaN/Infinity; one odd value must not break fetch_all
        # or make the output invalid JSON for the browser.
        self.mock.fixtures["wlan"]["band6"]["host"]["channel_width"] = float("inf")
        self.mock.fixtures["performance"]["cpu_usage"] = float("nan")
        self.mock.fixtures["device_list"][1]["signal_strength"]["band5"] = float("-inf")
        data = self.client().fetch_all()
        json.dumps(data, allow_nan=False)
        self.assertEqual(data["errors"], {})
        self.assertIsNone(data["wifi"]["bands"]["band6"]["width_mhz"])
        self.assertIsNone(data["performance"]["cpu_pct"])
        self.assertIsNone(data["nodes"][1]["signal_dbm"]["band5"])

    def test_width_normaliser_with_non_finite_numbers(self):
        for width in (float("inf"), float("-inf"), float("nan"), 1e400):
            with self.subTest(width=width):
                cfg = normalize_wlan({"band5": {"host": {"channel_width": width}}})
                self.assertIsNone(cfg["bands"]["band5"]["width_mhz"])


class NormaliserOddTypeTests(unittest.TestCase):
    def test_nodes_with_odd_clients(self):
        for clients in (5, "x", {"a": 1}, [{"online": True, "node_mac": ["x"]}],
                        [{"online": True, "node_mac": {"m": 1}}], [None, 3]):
            with self.subTest(clients=clients):
                nodes = normalize_nodes(X50_DEVICE_LIST, clients)
                self.assertEqual([n["client_count"] for n in nodes], [0, 0])


class NodeMappingTests(MockDecoTestCase):
    def test_device_mac_on_client_used_when_per_node_lists_fail(self):
        # SPEC: node_mac = which Deco it is attached to, if known (access_host / device_mac).
        for item in self.mock.fixtures["client_list"]:
            item["device_mac"] = self.mock.fixtures["client_nodes"][item["mac"]]
        self.mock.fail_forms = {"client_list:per_node": 500}
        data = self.client().fetch_all()
        self.assertIn("client_list_per_node", data["errors"])
        by_name = {c["name"]: c for c in data["clients"]}
        self.assertEqual(by_name["PS5"]["node_mac"], normalize_mac(OFFICE_MAC))
        self.assertEqual(by_name["MacBook Air"]["node_mac"], normalize_mac(MAIN_MAC))
        self.assertEqual([n["client_count"] for n in data["nodes"]], [3, 3, 2])

    def test_per_node_answer_wins_over_access_host(self):
        for item in self.mock.fixtures["client_list"]:
            item["access_host"] = MAIN_MAC  # disagrees with the per-node lists
        data = self.client().fetch_all()
        self.assertEqual([n["client_count"] for n in data["nodes"]], [3, 3, 2])

    def test_unknown_access_host_mac_is_not_trusted(self):
        for item in self.mock.fixtures["client_list"]:
            item["access_host"] = "11:22:33:44:55:66"  # not one of our Decos
        self.mock.fail_forms = {"client_list:per_node": 500}
        data = self.client().fetch_all()
        self.assertTrue(all(c["node_mac"] is None for c in data["clients"]))


if __name__ == "__main__":
    unittest.main()
