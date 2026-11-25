"""Tests for latency, speedtest and dns_check. Everything stays on 127.0.0.1."""

from __future__ import annotations

import socket
import ssl
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from decodash.measure import dns_check, latency, speedtest

CHUNK = 64 * 1024
ZEROS = b"\0" * CHUNK


class _SpeedHandler(BaseHTTPRequestHandler):
    """Tiny stand-in for speed.cloudflare.com: /__down and /__up."""

    protocol_version = "HTTP/1.1"
    delay_per_chunk = 0.002  # about 32 MB/s per connection, kind to the CPU
    user_agents: list = []

    def log_message(self, *args):  # keep test output clean
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path != "/__down":
            self.send_error(404)
            return
        self.user_agents.append(self.headers.get("User-Agent"))
        size = int(parse_qs(parts.query).get("bytes", ["0"])[0])
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        left = size
        try:
            while left > 0:
                n = min(CHUNK, left)
                self.wfile.write(ZEROS[:n])
                left -= n
                if self.delay_per_chunk:
                    time.sleep(self.delay_per_chunk)
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True

    def do_POST(self):
        if urlsplit(self.path).path != "/__up":
            self.send_error(404)
            return
        self.user_agents.append(self.headers.get("User-Agent"))
        left = int(self.headers.get("Content-Length") or 0)
        try:
            while left > 0:
                data = self.rfile.read(min(CHUNK, left))
                if not data:
                    self.close_connection = True
                    return
                left -= len(data)
                if self.delay_per_chunk:
                    time.sleep(self.delay_per_chunk)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):  # aborted streams are normal
        pass


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class SpeedtestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _QuietServer(("127.0.0.1", 0), _SpeedHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_full_run_against_local_server(self):
        calls = []
        started = time.monotonic()
        result = speedtest.run_speedtest(
            self.base, seconds=1.5, streams=2,
            progress_cb=lambda f, m: calls.append((f, m)), timeout=5.0,
        )
        elapsed = time.monotonic() - started
        for key in speedtest.RESULT_KEYS:
            self.assertIn(key, result)
        self.assertIsNone(result["error"], result["error"])
        self.assertGreater(result["down_mbps"], 0)
        self.assertGreater(result["up_mbps"], 0)
        self.assertIsNotNone(result["idle_latency_ms"])
        self.assertIsNotNone(result["loaded_latency_down_ms"])
        self.assertIsNotNone(result["loaded_latency_up_ms"])
        self.assertIsNotNone(result["bufferbloat_ms"])
        self.assertGreaterEqual(result["bufferbloat_ms"], 0)
        self.assertIn(result["bufferbloat_grade"], ("A+", "A", "B", "C", "D", "F"))
        self.assertEqual(result["server"], "127.0.0.1:%d" % self.server.server_address[1])
        self.assertGreater(result["duration_s"], 2.5)
        self.assertLess(elapsed, 15)
        # progress: fractions only go up, and the last call is 1.0
        fractions = [f for f, _m in calls]
        self.assertGreater(len(fractions), 5)
        self.assertEqual(fractions, sorted(fractions))
        self.assertEqual(fractions[-1], 1.0)
        self.assertTrue(all(0.0 <= f <= 1.0 for f in fractions))
        self.assertTrue(any(0.1 < f < 0.55 for f in fractions))
        self.assertTrue(any(0.55 < f < 1.0 for f in fractions))
        self.assertIn("decodash/1.0", _SpeedHandler.user_agents)

    def test_server_down_gives_error_not_exception(self):
        calls = []
        started = time.monotonic()
        result = speedtest.run_speedtest(
            "http://127.0.0.1:%d" % _free_port(), seconds=1.0, streams=2,
            progress_cb=lambda f, m: calls.append(f), timeout=2.0,
        )
        self.assertLess(time.monotonic() - started, 10)
        self.assertIsInstance(result["error"], str)
        self.assertTrue(result["error"])
        self.assertIsNone(result["down_mbps"])
        self.assertIsNone(result["up_mbps"])
        for key in speedtest.RESULT_KEYS:
            self.assertIn(key, result)
        self.assertEqual(calls[-1], 1.0)

    def test_bad_url_and_broken_callback(self):
        result = speedtest.run_speedtest("ftp://example.invalid", seconds=1)
        self.assertTrue(result["error"])

        def explode(fraction, message):
            raise RuntimeError("callback broke")

        result = speedtest.run_speedtest("http://127.0.0.1:%d" % _free_port(),
                                         seconds=0.5, streams=1, progress_cb=explode,
                                         timeout=1.0)
        self.assertTrue(result["error"])

    def test_friendly_cert_message(self):
        exc = ssl.SSLCertVerificationError(1, "certificate verify failed")
        message = speedtest._friendly_error(exc)
        self.assertIn("Install Certificates.command", message)
        self.assertIn("python.org", message)
        self.assertIn("429", speedtest._friendly_error(speedtest._HTTPStatusError(429)))

    def test_window_mbps_ignores_ramp_up(self):
        # 1 MB in the first second (ramp-up), then 10 MB/s for 2 s.
        samples = [(0.0, 0), (1.0, 1000000), (2.0, 11000000), (3.0, 21000000)]
        self.assertAlmostEqual(speedtest._window_mbps(samples, 1.0), 80.0)
        self.assertIsNone(speedtest._window_mbps([(0.0, 0), (1.0, 0)], 0.5))


class BufferbloatGradeTests(unittest.TestCase):
    def test_thresholds(self):
        grade = speedtest.bufferbloat_grade
        self.assertIsNone(grade(None))
        self.assertEqual(grade(0), "A+")
        self.assertEqual(grade(4.9), "A+")
        self.assertEqual(grade(5), "A")
        self.assertEqual(grade(29.9), "A")
        self.assertEqual(grade(30), "B")
        self.assertEqual(grade(59.9), "B")
        self.assertEqual(grade(60), "C")
        self.assertEqual(grade(199.9), "C")
        self.assertEqual(grade(200), "D")
        self.assertEqual(grade(399.9), "D")
        self.assertEqual(grade(400), "F")
        self.assertEqual(grade(5000), "F")
        self.assertIsNone(grade("not a number"))
        self.assertIsNone(grade(float("nan")))


class TcpPingTests(unittest.TestCase):
    def test_listening_socket(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        try:
            port = listener.getsockname()[1]
            rtt = latency.tcp_ping("127.0.0.1", port, timeout=2.0)
            self.assertIsInstance(rtt, float)
            self.assertGreaterEqual(rtt, 0.0)
            self.assertLess(rtt, 2000.0)
        finally:
            listener.close()

    def test_closed_port_counts_as_round_trip(self):
        rtt = latency.tcp_ping("127.0.0.1", _free_port(), timeout=2.0)
        self.assertIsInstance(rtt, float)  # refused = the other side answered

    def test_timeout_and_errors_are_loss(self):
        with mock.patch.object(latency.socket, "create_connection",
                               side_effect=socket.timeout("timed out")):
            self.assertIsNone(latency.tcp_ping("127.0.0.1", 80, timeout=0.1))
        with mock.patch.object(latency.socket, "create_connection",
                               side_effect=OSError("network unreachable")):
            self.assertIsNone(latency.tcp_ping("127.0.0.1", 80, timeout=0.1))
        self.assertIsNone(latency.tcp_ping("", 80))

    def test_host_cleanup(self):
        self.assertEqual(latency._clean_host("http://192.168.68.1/"), "192.168.68.1")
        self.assertEqual(latency._clean_host("192.168.68.1:8080"), "192.168.68.1")
        self.assertEqual(latency._clean_host("[fe80::1]:80"), "fe80::1")


class MeasureLatencyTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(latency, "SAMPLE_INTERVAL_S", 0.0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_gateway_falls_back_to_443_and_stats(self):
        lock = threading.Lock()
        sequences = {
            ("1.1.1.1", 443): [10.0, 12.0, None, 11.0, 13.0],
            ("8.8.8.8", 443): [20.0, 20.0, 20.0, 20.0, 20.0],
        }

        def fake_ping(host, port, timeout=2.0):
            if host == "192.168.68.1":
                return None if port == 80 else 3.0
            with lock:
                return sequences[(host, port)].pop(0)

        with mock.patch.object(latency, "tcp_ping", side_effect=fake_ping):
            result = latency.measure_latency("192.168.68.1", count=5, timeout=0.5)

        self.assertIsNone(result["error"])
        self.assertTrue(result["measured_at"])
        gateway = result["gateway"]
        self.assertEqual(gateway["name"], "Your Deco")
        self.assertEqual(gateway["port"], 443)
        self.assertEqual(gateway["median_ms"], 3.0)
        self.assertEqual(gateway["loss_pct"], 0.0)

        cloudflare, google = result["internet"]
        self.assertEqual((cloudflare["name"], cloudflare["host"], cloudflare["port"]),
                         ("Cloudflare", "1.1.1.1", 443))
        self.assertEqual(cloudflare["samples_ms"], [10.0, 12.0, 11.0, 13.0])
        self.assertEqual(cloudflare["loss_pct"], 20.0)
        self.assertEqual(cloudflare["median_ms"], 11.5)
        self.assertEqual(cloudflare["p90_ms"], 13.0)
        self.assertAlmostEqual(cloudflare["jitter_ms"], (2 + 1 + 2) / 3.0, places=2)
        self.assertEqual(google["name"], "Google")
        self.assertEqual(google["jitter_ms"], 0.0)
        self.assertEqual(google["loss_pct"], 0.0)

    def test_everything_down(self):
        with mock.patch.object(latency, "tcp_ping", return_value=None):
            result = latency.measure_latency("192.168.68.1", count=15, timeout=0.1)
        self.assertTrue(result["error"])
        self.assertEqual(result["gateway"]["loss_pct"], 100.0)
        self.assertEqual(result["gateway"]["port"], 80)
        self.assertIsNone(result["gateway"]["median_ms"])
        for target in result["internet"]:
            self.assertEqual(target["loss_pct"], 100.0)
            self.assertIsNone(target["jitter_ms"])

    def test_no_gateway_and_never_raises(self):
        with mock.patch.object(latency, "tcp_ping", return_value=5.0):
            result = latency.measure_latency(None, count=3)
        self.assertIsNone(result["gateway"])
        self.assertEqual(len(result["internet"]), 2)
        with mock.patch.object(latency, "tcp_ping", side_effect=RuntimeError("boom")):
            result = latency.measure_latency("192.168.68.1", count=2)
        self.assertIsInstance(result, dict)
        self.assertTrue(result["error"])


class MeasureDnsTests(unittest.TestCase):
    def setUp(self):
        self.release = threading.Event()
        self.addCleanup(self.release.set)
        patcher = mock.patch.object(dns_check, "get_resolvers", return_value=["192.168.68.1"])
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_getaddrinfo(self, host, port, *args, **kwargs):
        if host.startswith("hang"):
            self.release.wait(5)
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
        if host.startswith("nx") or host.startswith("q"):
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        if host.startswith("broken"):
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", port))]

    def test_custom_hosts_with_hanging_resolver(self):
        started = time.monotonic()
        with mock.patch("decodash.measure.dns_check.socket.getaddrinfo",
                        side_effect=self.fake_getaddrinfo):
            result = dns_check.measure_dns(
                ["good.example", "nx.example", "hang.example", "broken.example"], timeout=0.3)
        self.assertLess(time.monotonic() - started, 3.0)
        by_host = {s["host"]: s for s in result["samples"]}
        self.assertTrue(by_host["good.example"]["ok"])
        self.assertIsInstance(by_host["good.example"]["ms"], float)
        self.assertTrue(by_host["nx.example"]["ok"])  # NXDOMAIN is still an answer
        self.assertFalse(by_host["hang.example"]["ok"])
        self.assertIsNone(by_host["hang.example"]["ms"])
        self.assertFalse(by_host["broken.example"]["ok"])
        self.assertIsNotNone(result["median_ms"])
        self.assertEqual(result["resolvers"], ["192.168.68.1"])
        self.assertIsNone(result["error"])
        self.assertTrue(result["measured_at"])

    def test_default_hosts_include_three_uncached_lookups(self):
        seen = []

        def record(host, port, *args, **kwargs):
            seen.append(host)
            return self.fake_getaddrinfo(host, port)

        with mock.patch("decodash.measure.dns_check.socket.getaddrinfo", side_effect=record):
            result = dns_check.measure_dns()
        uncached = [s for s in result["samples"] if s.get("uncached")]
        self.assertEqual(len(uncached), 3)
        self.assertTrue(all(s["ok"] for s in result["samples"]))
        self.assertEqual(len(seen), len(dns_check.POPULAR_HOSTS) + 3)
        parents = {h.split(".", 1)[1] for h in seen[-3:]}
        self.assertEqual(parents, set(dns_check.UNCACHED_PARENTS))
        self.assertIsNotNone(result["uncached_median_ms"])
        # random labels are different every run
        with mock.patch("decodash.measure.dns_check.socket.getaddrinfo",
                        side_effect=self.fake_getaddrinfo):
            again = dns_check.measure_dns()
        self.assertNotEqual([s["host"] for s in again["samples"][-3:]], seen[-3:])

    def test_dns_completely_down_stops_early(self):
        started = time.monotonic()
        with mock.patch("decodash.measure.dns_check.socket.getaddrinfo",
                        side_effect=self.fake_getaddrinfo):
            result = dns_check.measure_dns(
                ["hang1.example", "hang2.example", "hang3.example", "hang4.example"],
                timeout=0.2)
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertTrue(result["error"])
        self.assertIsNone(result["median_ms"])
        self.assertFalse(any(s["ok"] for s in result["samples"]))
        self.assertEqual(len(result["samples"]), 4)

    def test_not_found_everywhere_is_not_trusted(self):
        with mock.patch("decodash.measure.dns_check.socket.getaddrinfo",
                        side_effect=self.fake_getaddrinfo):
            result = dns_check.measure_dns(["nx1.example", "nx2.example"], timeout=0.5)
        self.assertFalse(any(s["ok"] for s in result["samples"]))
        self.assertTrue(result["error"])

    def test_never_raises(self):
        with mock.patch.object(dns_check, "_plan", side_effect=RuntimeError("boom")):
            result = dns_check.measure_dns()
        self.assertIn("boom", result["error"])
        for key in ("median_ms", "samples", "resolvers", "measured_at", "error"):
            self.assertIn(key, result)


class ResolverParsingTests(unittest.TestCase):
    def test_resolv_conf(self):
        text = ("# Generated by NetworkManager\nsearch lan\nnameserver 192.168.68.1\n"
                "nameserver 1.1.1.1 # backup\nnameserver fe80::1%en0\nnameserver 1.1.1.1\n"
                "options edns0\n")
        self.assertEqual(dns_check.parse_resolv_conf(text),
                         ["192.168.68.1", "1.1.1.1", "fe80::1%en0"])

    def test_ipconfig_all(self):
        text = """
Wireless LAN adapter Wi-Fi:

   Description . . . . . . . . . . . : Intel(R) Wi-Fi 7 BE200 320MHz
   Default Gateway . . . . . . . . . : 192.168.68.1
   DHCP Server . . . . . . . . . . . : 192.168.68.1
   DNS Servers . . . . . . . . . . . : 192.168.68.1
                                       8.8.8.8
                                       fe80::3268:93ff:feaa:bbcc%12
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter Bluetooth Network Connection:

   Media State . . . . . . . . . . . : Media disconnected
"""
        self.assertEqual(dns_check.parse_ipconfig_dns(text),
                         ["192.168.68.1", "8.8.8.8", "fe80::3268:93ff:feaa:bbcc%12"])



# ---------------------------------------------------------------------------
# Adversarial review tests
# ---------------------------------------------------------------------------

class _CountingUploadHandler(_SpeedHandler):
    """Like _SpeedHandler, but remembers how many upload bytes really arrived."""

    received = [0]
    lock = threading.Lock()
    delay_per_chunk = 0.004

    def do_POST(self):
        left = int(self.headers.get("Content-Length") or 0)
        try:
            while left > 0:
                data = self.rfile.read(min(CHUNK, left))
                if not data:
                    self.close_connection = True
                    return
                with self.lock:
                    self.received[0] += len(data)
                left -= len(data)
                time.sleep(self.delay_per_chunk)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except OSError:
            self.close_connection = True


class _TooManyRequestsHandler(_SpeedHandler):
    def do_GET(self):
        self.send_response(429)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _DropsKeepAliveHandler(_SpeedHandler):
    """Answers each request, then silently closes the kept-alive connection."""

    received = [0]
    lock = threading.Lock()

    def do_GET(self):
        super().do_GET()
        self.close_connection = True

    def do_POST(self):
        left = int(self.headers.get("Content-Length") or 0)
        try:
            while left > 0:
                data = self.rfile.read(min(CHUNK, left))
                if not data:
                    return
                with self.lock:
                    self.received[0] += len(data)
                left -= len(data)
                time.sleep(self.delay_per_chunk)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except OSError:
            pass
        self.close_connection = True


class _EmptyAnswerHandler(_SpeedHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


class ReviewSpeedtestTests(unittest.TestCase):
    def serve(self, handler):
        server = _QuietServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, "http://127.0.0.1:%d" % server.server_address[1]

    def test_upload_counts_bytes_that_were_really_sent(self):
        _CountingUploadHandler.received[0] = 0
        _server, base = self.serve(_CountingUploadHandler)
        target = speedtest._Server(base, 5.0)
        phase = speedtest._run_phase("upload", target, 1.0, 2, None, 1.0, 0.25,
                                     lambda f, m: None, 0.55, 1.0)
        time.sleep(0.3)  # let the server finish reading what is in flight
        got = _CountingUploadHandler.received[0]
        self.assertGreater(got, 0)
        self.assertGreater(phase["bytes"], 0)
        # The client can never claim fewer bytes than the server received.
        self.assertGreaterEqual(phase["bytes"], got)
        self.assertIsNotNone(phase["mbps"])
        self.assertGreater(phase["mbps"], 0)

    def test_streams_survive_a_server_that_drops_kept_alive_connections(self):
        # Before the fix, 3 harmless reconnects (spread over the whole test)
        # killed each stream, so the test stopped after a fraction of its time.
        _server, base = self.serve(_DropsKeepAliveHandler)
        target = speedtest._Server(base, 5.0)
        with mock.patch.object(speedtest, "DOWN_BYTES_PER_REQUEST", 300000), \
                mock.patch.object(speedtest, "UP_BYTES_PER_REQUEST", 300000):
            for kind in ("download", "upload"):
                _DropsKeepAliveHandler.received[0] = 0
                phase = speedtest._run_phase(kind, target, 1.5, 2, None, 1.0, 0.25,
                                             lambda f, m: None, 0.0, 1.0)
                self.assertGreater(phase["elapsed"], 1.4, kind)
                self.assertGreater(phase["mbps"] or 0, 0, kind)
                self.assertEqual(phase["errors"], [], kind)  # reconnecting isn't an error
                if kind == "upload":
                    time.sleep(0.3)
                    got = _DropsKeepAliveHandler.received[0]
                    # Bytes pushed into a connection the server had already
                    # closed never arrive, so they must not be counted.
                    self.assertLessEqual(phase["bytes"], got + 4 * 1024 * 1024)

    def test_empty_answers_stop_instead_of_spinning(self):
        _server, base = self.serve(_EmptyAnswerHandler)
        started = time.monotonic()
        result = speedtest.run_speedtest(base, seconds=1.0, streams=2, timeout=2.0)
        self.assertLess(time.monotonic() - started, 6)
        self.assertIsNone(result["down_mbps"])
        self.assertIn("empty", result["error"])

    def test_http_429_gives_friendly_error(self):
        _server, base = self.serve(_TooManyRequestsHandler)
        result = speedtest.run_speedtest(base, seconds=0.5, streams=2, timeout=2.0)
        self.assertIsNone(result["down_mbps"])
        self.assertIn("429", result["error"])

    def test_odd_arguments_never_raise(self):
        _server, base = self.serve(_SpeedHandler)
        started = time.monotonic()
        result = speedtest.run_speedtest(base, seconds=0, streams=0, timeout="soon",
                                         progress_cb=None)
        self.assertLess(time.monotonic() - started, 15)
        for key in speedtest.RESULT_KEYS:
            self.assertIn(key, result)
        self.assertIsNone(result["error"], result["error"])
        self.assertGreater(result["down_mbps"], 0)
        # (None and "" mean "use Cloudflare", so they are not tried here: no internet.)
        with mock.patch.object(speedtest.socket, "getaddrinfo",
                               side_effect=AssertionError("must not look anything up")):
            for bad in ("   ", "http://", "http://[::1", "https://host:99999/", 12345):
                result = speedtest.run_speedtest(bad, seconds=0.5, streams=1, timeout=0.5)
                self.assertIsInstance(result, dict)
                self.assertIsInstance(result["server"], str)
                self.assertTrue(result["error"], bad)

    def test_server_label_never_shows_a_password(self):
        result = speedtest.run_speedtest("ftp://user:hunter2@example.invalid/", seconds=0.5)
        self.assertNotIn("hunter2", result["server"])
        self.assertNotIn("hunter2", str(result["error"]))
        target = speedtest._Server("https://user:hunter2@speed.example.com:8443/x", 5.0)
        self.assertEqual(target.display, "speed.example.com:8443")
        self.assertEqual(speedtest._Server("https://speed.cloudflare.com", 5.0).display,
                         "speed.cloudflare.com")
        self.assertEqual(speedtest._Server("http://[::1]:8080", 5.0).display, "[::1]:8080")

    def test_mbps_maths_on_tiny_and_empty_runs(self):
        window = speedtest._window_mbps
        self.assertIsNone(window([], 1.0))
        self.assertIsNone(window([(0.0, 0)], 1.0))
        self.assertIsNone(window([(0.0, 0), (0.0, 0)], 0.1))
        self.assertIsNone(window([(0.0, 100)], 0.1))  # no time passed: no division by zero
        # 1,000,000 bytes in 1 s is 8 Mbps (bits, not bytes)
        self.assertAlmostEqual(window([(0.0, 0), (1.0, 1000000)], 5.0), 8.0)
        # Too short a window after ramp-up falls back to the whole run.
        self.assertAlmostEqual(window([(0.0, 0), (0.5, 500000), (0.6, 600000)], 0.5), 8.0)
        recent = speedtest._recent_mbps
        self.assertEqual(recent([]), 0.0)
        self.assertEqual(recent([(1.0, 5)]), 0.0)
        self.assertEqual(recent([(1.0, 5), (1.0, 10)]), 0.0)
        self.assertAlmostEqual(recent([(0.0, 0), (0.5, 0), (1.5, 1000000)]), 8.0)

    def test_grade_odd_values(self):
        self.assertEqual(speedtest.bufferbloat_grade(-3), "A+")
        self.assertEqual(speedtest.bufferbloat_grade(float("inf")), "F")
        self.assertIsNone(speedtest.bufferbloat_grade(True))
        self.assertEqual(speedtest.bufferbloat_grade("45"), "B")


class ReviewLatencyTests(unittest.TestCase):
    def test_hostname_lookup_respects_the_timeout(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def stuck_lookup(*args, **kwargs):
            release.wait(10)
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")

        with mock.patch.object(latency.socket, "getaddrinfo", side_effect=stuck_lookup):
            started = time.monotonic()
            self.assertIsNone(latency.tcp_ping("deco.example", 80, timeout=0.3))
            self.assertLess(time.monotonic() - started, 2.0)

    def test_hostname_is_resolved_then_pinged(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        answer = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
                  (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        with mock.patch.object(latency.socket, "getaddrinfo", return_value=answer):
            rtt = latency.tcp_ping("deco.example", port, timeout=2.0)
        self.assertIsInstance(rtt, float)

    def test_odd_arguments_are_loss_not_crashes(self):
        self.assertIsNone(latency.tcp_ping(None, 80))
        self.assertIsNone(latency.tcp_ping("127.0.0.1", "http"))
        self.assertIsNone(latency.tcp_ping("127.0.0.1", 70000, timeout=0.2))
        # A NaN timeout falls back to the default instead of breaking the socket call.
        self.assertIsInstance(latency.tcp_ping("127.0.0.1", _free_port(), timeout=float("nan")),
                              float)
        with mock.patch.object(latency, "tcp_ping", return_value=4.0), \
                mock.patch.object(latency, "SAMPLE_INTERVAL_S", 0.0):
            result = latency.measure_latency("http://192.168.68.1/", count="lots",
                                             timeout=-1)
            self.assertEqual(result["gateway"]["host"], "192.168.68.1")
            self.assertEqual(len(result["gateway"]["samples_ms"]), 15)
            result = latency.measure_latency("192.168.68.1", count=0)
            self.assertEqual(len(result["gateway"]["samples_ms"]), 1)
            self.assertIsNone(result["gateway"]["jitter_ms"])
            self.assertEqual(result["gateway"]["p90_ms"], 4.0)


class ReviewDnsTests(unittest.TestCase):
    def test_subprocess_survives_endless_timeout(self):
        import sys
        out = dns_check._run([sys.executable, "-c", "print('hi')"], float("inf"))
        self.assertEqual((out or "").strip(), "hi")

    def test_hanging_lookup_thread_does_not_block_return(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def stuck(*args, **kwargs):
            release.wait(10)
            return []

        with mock.patch.object(dns_check, "get_resolvers", return_value=[]), \
                mock.patch("decodash.measure.dns_check.socket.getaddrinfo", side_effect=stuck):
            started = time.monotonic()
            result = dns_check.measure_dns(timeout=0.2)
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(len(result["samples"]), len(dns_check.POPULAR_HOSTS) + 3)
        self.assertTrue(all(not s["ok"] for s in result["samples"]))
        self.assertTrue(result["error"])


if __name__ == "__main__":
    unittest.main()
