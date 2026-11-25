"""Internet speed test: download, upload and bufferbloat.

It talks to Cloudflare's public speed test endpoints (``GET /__down?bytes=N``
and ``POST /__up``) with several parallel connections, like real apps do.
While data is flowing it keeps pinging the server: if the ping shoots up
under load, that's "bufferbloat" (data piling up in a queue somewhere).
``run_speedtest()`` never raises.
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import statistics
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Tuple
from urllib.parse import urlsplit

from . import latency as _latency

DEFAULT_BASE_URL = "https://speed.cloudflare.com"
USER_AGENT = "decodash/1.0"
DOWN_BYTES_PER_REQUEST = 25000000
UP_BYTES_PER_REQUEST = 25000000
CHUNK_BYTES = 64 * 1024
UPLOAD_BUFFER_BYTES = 1024 * 1024
SAMPLE_EVERY_S = 0.1
LOADED_PING_EVERY_S = 0.25
IDLE_PINGS = 5
MAX_RETRIES_PER_STREAM = 3

RESULT_KEYS = (
    "down_mbps", "up_mbps", "idle_latency_ms", "loaded_latency_down_ms",
    "loaded_latency_up_ms", "bufferbloat_ms", "bufferbloat_grade", "server",
    "duration_s", "measured_at", "error",
)

_CERT_HELP = (
    "Your computer couldn't check the speed test server's security certificate. "
    "If you use the python.org version of Python on a Mac, open Applications → "
    "Python 3.x and double-click \"Install Certificates.command\" once, then try again."
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def bufferbloat_grade(ms: float | None) -> str | None:
    """A+ (<5 ms extra under load), A (<30), B (<60), C (<200), D (<400), else F."""
    if ms is None or isinstance(ms, bool):
        return None
    try:
        value = float(ms)
    except (TypeError, ValueError):
        return None
    if value != value:  # NaN
        return None
    if value < 5:
        return "A+"
    if value < 30:
        return "A"
    if value < 60:
        return "B"
    if value < 200:
        return "C"
    if value < 400:
        return "D"
    return "F"


class _HTTPStatusError(Exception):
    def __init__(self, status: int, reason: str = "") -> None:
        super().__init__("HTTP %s %s" % (status, reason))
        self.status = status


def _friendly_error(exc: BaseException | None, what: str = "the speed test server") -> str:
    if exc is None:
        return "No data came back from %s." % what
    if isinstance(exc, ssl.SSLCertVerificationError):
        return _CERT_HELP
    if isinstance(exc, _HTTPStatusError):
        if exc.status == 429:
            return ("The speed test server is limiting tests right now (HTTP 429). "
                    "Wait a minute and try again.")
        return "The speed test server answered with an error (HTTP %s)." % exc.status
    if isinstance(exc, ssl.SSLError):
        return "The secure connection to %s failed (%s)." % (what, exc)
    if isinstance(exc, socket.gaierror):
        return ("Couldn't find the address of %s. Check that this computer is online "
                "(this can also be a DNS problem)." % what)
    if isinstance(exc, ConnectionRefusedError):
        return "Couldn't connect: %s refused the connection." % what
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "No answer in time: %s took too long to respond." % what
    if isinstance(exc, ValueError):
        return str(exc)
    if isinstance(exc, OSError):
        return "Couldn't reach %s (%s)." % (what, exc)
    return "The speed test hit a problem: %s" % (exc,)


def _display_name(host: str, port: int | None) -> str:
    shown = "[%s]" % host if ":" in host else host
    return shown if port is None else "%s:%d" % (shown, port)


def _safe_server_label(base_url: Any) -> str:
    """The server's host[:port] for the result, without any login details."""
    try:
        parts = urlsplit(str(base_url or DEFAULT_BASE_URL).strip())
        if parts.hostname:
            return _display_name(parts.hostname, parts.port)
    except Exception:  # bad port number, odd object, ...
        pass
    return ""


class _Server:
    """Where to send the test traffic, parsed from base_url."""

    def __init__(self, base_url: str, timeout: float) -> None:
        parts = urlsplit(str(base_url or DEFAULT_BASE_URL).strip())
        scheme = (parts.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ValueError("The speed test address must start with http:// or https://.")
        if not parts.hostname:
            raise ValueError("The speed test address is missing a server name.")
        self.https = scheme == "https"
        self.host = parts.hostname
        self.port = parts.port or (443 if self.https else 80)
        self.prefix = parts.path.rstrip("/")
        self.display = _display_name(self.host, parts.port)  # never "user:password@..."
        self.timeout = timeout
        self.context = ssl.create_default_context() if self.https else None

    def connect(self) -> http.client.HTTPConnection:
        if self.https:
            return http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=self.context
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def down_path(self, size: int) -> str:
        return "%s/__down?bytes=%d" % (self.prefix, size)

    def up_path(self) -> str:
        return "%s/__up" % self.prefix


class _Transfer:
    """Shared state of one direction: byte counter, stop flag, connections."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.bytes = 0
        self.stop = threading.Event()
        self.errors: List[BaseException] = []
        self.conns: List[http.client.HTTPConnection] = []

    def add(self, count: int) -> None:
        with self.lock:
            self.bytes += count

    def total(self) -> int:
        with self.lock:
            return self.bytes

    def error(self, exc: BaseException) -> None:
        with self.lock:
            self.errors.append(exc)

    def register(self, conn: http.client.HTTPConnection) -> None:
        with self.lock:
            self.conns.append(conn)

    def unregister(self, conn: http.client.HTTPConnection) -> None:
        with self.lock:
            if conn in self.conns:
                self.conns.remove(conn)

    def abort_all(self) -> None:
        """Wake up every stream by shutting its socket down."""
        with self.lock:
            conns = list(self.conns)
        for conn in conns:
            sock = getattr(conn, "sock", None)
            if sock is None:
                continue
            try:
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except Exception:
                pass


def _close(conn: http.client.HTTPConnection | None) -> None:
    if conn is None:
        return
    try:
        conn.close()
    except Exception:
        pass


def _fatal(exc: BaseException) -> bool:
    """Errors where retrying makes no sense."""
    return isinstance(exc, (ssl.SSLCertVerificationError, _HTTPStatusError,
                            socket.gaierror, ConnectionRefusedError, ValueError))


def _stale(exc: BaseException, served: int) -> bool:
    """A kept-alive connection the server quietly closed after an earlier
    answer. That's normal: reconnect at once and don't count it as a failure."""
    return served > 0 and isinstance(exc, (ConnectionResetError, BrokenPipeError,
                                           ConnectionAbortedError, ssl.SSLEOFError))


def _download_worker(server: _Server, state: _Transfer, deadline: float) -> None:
    buffer = memoryview(bytearray(CHUNK_BYTES))
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity",
               "Cache-Control": "no-store"}
    conn = None
    failures = 0
    served = 0  # complete answers on the current connection
    try:
        while not state.stop.is_set() and time.perf_counter() < deadline:
            try:
                if conn is None:
                    conn = server.connect()
                    state.register(conn)
                    served = 0
                conn.request("GET", server.down_path(DOWN_BYTES_PER_REQUEST), headers=headers)
                response = conn.getresponse()
                if response.status != 200:
                    raise _HTTPStatusError(response.status, response.reason)
                finished = False
                got = 0
                while True:
                    if state.stop.is_set() or time.perf_counter() >= deadline:
                        break
                    count = response.readinto(buffer)
                    if not count:
                        finished = True
                        break
                    state.add(count)
                    got += count
                if not finished:
                    break  # time is up: stop by closing the connection
                if not got:  # a 200 with no data: asking again won't help
                    raise ValueError("The speed test server sent an empty answer.")
                failures = 0  # only failures in a row end the stream
                served += 1
                if response.will_close:
                    state.unregister(conn)
                    _close(conn)
                    conn = None
            except Exception as exc:
                if state.stop.is_set() or time.perf_counter() >= deadline:
                    break
                if conn is not None:
                    state.unregister(conn)
                    _close(conn)
                    conn = None
                if _stale(exc, served):
                    continue
                state.error(exc)
                failures += 1
                if _fatal(exc) or failures >= MAX_RETRIES_PER_STREAM:
                    break
                time.sleep(0.2)
    finally:
        if conn is not None:
            state.unregister(conn)
            _close(conn)


def _upload_worker(server: _Server, state: _Transfer, deadline: float, payload: bytes) -> None:
    view = memoryview(payload)
    size = len(payload)
    conn = None
    failures = 0
    served = 0  # complete answers on the current connection
    try:
        while not state.stop.is_set() and time.perf_counter() < deadline:
            sent = 0
            try:
                if conn is None:
                    conn = server.connect()
                    state.register(conn)
                    served = 0
                conn.putrequest("POST", server.up_path(), skip_accept_encoding=True)
                conn.putheader("User-Agent", USER_AGENT)
                conn.putheader("Content-Type", "application/octet-stream")
                conn.putheader("Content-Length", str(UP_BYTES_PER_REQUEST))
                conn.endheaders()
                offset = 0
                while sent < UP_BYTES_PER_REQUEST:
                    if state.stop.is_set() or time.perf_counter() >= deadline:
                        break
                    count = min(CHUNK_BYTES, UP_BYTES_PER_REQUEST - sent, size - offset)
                    conn.send(view[offset:offset + count])
                    state.add(count)
                    sent += count
                    offset += count
                    if offset >= size:
                        offset = 0
                if sent < UP_BYTES_PER_REQUEST:
                    break  # time is up: stop by closing the connection
                response = conn.getresponse()
                response.read()
                if response.status != 200:
                    raise _HTTPStatusError(response.status, response.reason)
                failures = 0  # only failures in a row end the stream
                served += 1
                if response.will_close:
                    state.unregister(conn)
                    _close(conn)
                    conn = None
            except Exception as exc:
                if state.stop.is_set() or time.perf_counter() >= deadline:
                    break
                if conn is not None:
                    state.unregister(conn)
                    _close(conn)
                    conn = None
                if _stale(exc, served):
                    # The server had already closed this connection, so what we
                    # just pushed into it never arrived: don't count it.
                    if sent:
                        state.add(-sent)
                    continue
                state.error(exc)
                failures += 1
                if _fatal(exc) or failures >= MAX_RETRIES_PER_STREAM:
                    break
                time.sleep(0.2)
    finally:
        if conn is not None:
            state.unregister(conn)
            _close(conn)


def _sampler(state: _Transfer, t0: float, samples: List[Tuple[float, int]],
             stop: threading.Event) -> None:
    while True:
        samples.append((time.perf_counter() - t0, state.total()))
        if stop.wait(SAMPLE_EVERY_S):
            return


def _pinger(address: str, port: int, timeout: float, t0: float,
            out: List[Tuple[float, float | None]], stop: threading.Event) -> None:
    while not stop.is_set():
        rtt = _latency.tcp_ping(address, port, timeout)
        out.append((time.perf_counter() - t0, rtt))
        if stop.wait(LOADED_PING_EVERY_S):
            return


def _window_mbps(samples: List[Tuple[float, int]], ramp_s: float) -> float | None:
    points = sorted(samples)
    if not points or points[-1][1] <= 0:
        return None
    last_t, last_b = points[-1]
    start = None
    for point in points:
        if point[0] >= ramp_s:
            start = point
            break
    if start is not None and last_t - start[0] >= 0.25:
        return (last_b - start[1]) * 8 / 1e6 / (last_t - start[0])
    if last_t > 0:
        return last_b * 8 / 1e6 / last_t
    return None


def _recent_mbps(samples: List[Tuple[float, int]]) -> float:
    if len(samples) < 2:
        return 0.0
    last_t, last_b = samples[-1]
    for t, b in reversed(samples[:-1]):
        if last_t - t >= 1.0:
            return max(0.0, (last_b - b) * 8 / 1e6 / (last_t - t))
    first_t, first_b = samples[0]
    if last_t - first_t <= 0:
        return 0.0
    return max(0.0, (last_b - first_b) * 8 / 1e6 / (last_t - first_t))


def _run_phase(kind: str, server: _Server, seconds: float, streams: int,
               ping_address: str | None, ping_timeout: float, ramp_s: float,
               progress: Callable[[float, str], None], lo: float, hi: float) -> dict:
    state = _Transfer()
    samples: List[Tuple[float, int]] = []
    pings: List[Tuple[float, float | None]] = []
    helpers_stop = threading.Event()
    t0 = time.perf_counter()
    deadline = t0 + seconds

    if kind == "download":
        workers = [threading.Thread(target=_download_worker, args=(server, state, deadline),
                                    daemon=True) for _ in range(streams)]
    else:
        payload = os.urandom(UPLOAD_BUFFER_BYTES)  # random, so nothing can compress it
        workers = [threading.Thread(target=_upload_worker,
                                    args=(server, state, deadline, payload),
                                    daemon=True) for _ in range(streams)]
    helpers = [threading.Thread(target=_sampler, args=(state, t0, samples, helpers_stop),
                                daemon=True)]
    if ping_address:
        helpers.append(threading.Thread(
            target=_pinger,
            args=(ping_address, server.port, ping_timeout, t0, pings, helpers_stop),
            daemon=True))
    for thread in workers + helpers:
        thread.start()

    label = "download" if kind == "download" else "upload"
    while True:
        now = time.perf_counter()
        if now >= deadline or not any(w.is_alive() for w in workers):
            break
        fraction = lo + (hi - lo) * min(1.0, (now - t0) / seconds)
        progress(fraction, "Testing %s speed… %.0f Mbps" % (label, _recent_mbps(list(samples))))
        time.sleep(max(0.01, min(0.25, deadline - now)))

    end = time.perf_counter()
    samples.append((end - t0, state.total()))
    state.stop.set()
    helpers_stop.set()
    state.abort_all()
    join_until = time.perf_counter() + min(3.0, server.timeout)
    for thread in workers:
        thread.join(max(0.0, join_until - time.perf_counter()))
    helpers[0].join(0.5)
    if len(helpers) > 1:
        helpers[1].join(0.5)

    window = [s for s in samples if s[0] <= end - t0 + 1e-6]
    mbps = _window_mbps(window, ramp_s)
    return {
        "bytes": state.total(),
        "mbps": mbps,
        "errors": list(state.errors),
        "pings": list(pings),
        "elapsed": end - t0,
    }


def _loaded_latency(pings: List[Tuple[float, float | None]], ramp_s: float,
                    idle_ok: bool, ping_timeout: float) -> float | None:
    """Median ping while loaded, ignoring the ramp-up. A timed-out ping counts
    as "at least the timeout" when the idle ping worked."""
    def values(items: List[Tuple[float, float | None]]) -> List[float]:
        out: List[float] = []
        for _t, rtt in items:
            if rtt is not None:
                out.append(rtt)
            elif idle_ok:
                out.append(ping_timeout * 1000.0)
        return out

    after = values([p for p in pings if p[0] >= ramp_s])
    chosen = after if after else values(pings)
    if not chosen:
        return None
    return round(statistics.median(chosen), 2)


def _resolve(host: str, port: int, timeout: float) -> Tuple[str | None, BaseException | None]:
    box: Dict[str, Any] = {}

    def work() -> None:
        try:
            infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
            chosen = None
            for family, _type, _proto, _name, sockaddr in infos:
                if family == socket.AF_INET:
                    chosen = sockaddr[0]
                    break
            if chosen is None and infos:
                chosen = infos[0][4][0]
            box["address"] = chosen
        except BaseException as exc:  # noqa: BLE001 - reported to the caller
            box["error"] = exc

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return None, socket.timeout("DNS lookup timed out")
    return box.get("address"), box.get("error")


def run_speedtest(base_url: str = DEFAULT_BASE_URL, seconds: float = 8.0,
                  streams: int = 6, progress_cb=None, timeout: float = 10.0) -> dict:
    """SpeedResult. progress_cb(fraction, message) may be None. Never raises."""
    started = time.perf_counter()
    result: Dict[str, Any] = {key: None for key in RESULT_KEYS}
    result["server"] = _safe_server_label(base_url)
    result["duration_s"] = 0.0
    result["measured_at"] = _now_iso()
    last = [0.0]

    def progress(fraction: float, message: str) -> None:
        if progress_cb is None:
            return
        try:
            value = max(last[0], min(1.0, max(0.0, float(fraction))))
            last[0] = value
            progress_cb(value, message)
        except Exception:
            pass

    try:
        try:
            seconds = float(seconds)
        except (TypeError, ValueError):
            seconds = 8.0
        seconds = max(0.5, min(60.0, seconds if seconds == seconds else 8.0))
        try:
            streams = max(1, min(32, int(streams)))
        except (TypeError, ValueError):
            streams = 6
        timeout = _latency._clean_timeout(timeout, 10.0)
        ramp_s = min(1.0, seconds * 0.25)
        ping_timeout = min(timeout, 2.0)

        server = _Server(base_url, timeout)
        result["server"] = server.display

        progress(0.0, "Checking the ping to the speed test server…")
        address, dns_error = _resolve(server.host, server.port, min(timeout, 5.0))
        if address is None:
            result["error"] = _friendly_error(dns_error or socket.gaierror("no address"))
            return result

        idle: List[float] = []
        for i in range(IDLE_PINGS):
            rtt = _latency.tcp_ping(address, server.port, ping_timeout)
            if rtt is not None:
                idle.append(rtt)
            progress(0.1 * (i + 1) / IDLE_PINGS, "Checking the ping to the speed test server…")
            if i < IDLE_PINGS - 1:
                time.sleep(0.05)
        idle_ms = round(statistics.median(idle), 2) if idle else None
        result["idle_latency_ms"] = idle_ms

        progress(0.1, "Testing download speed…")
        down = _run_phase("download", server, seconds, streams, address, ping_timeout,
                          ramp_s, progress, 0.1, 0.55)
        if down["bytes"] <= 0 or down["mbps"] is None:
            first = down["errors"][0] if down["errors"] else None
            result["error"] = _friendly_error(first)
            return result
        result["down_mbps"] = round(down["mbps"], 1)
        result["loaded_latency_down_ms"] = _loaded_latency(
            down["pings"], ramp_s, idle_ms is not None, ping_timeout)

        progress(0.55, "Testing upload speed…")
        up = _run_phase("upload", server, seconds, streams, address, ping_timeout,
                        ramp_s, progress, 0.55, 1.0)
        if up["bytes"] > 0 and up["mbps"] is not None:
            result["up_mbps"] = round(up["mbps"], 1)
            result["loaded_latency_up_ms"] = _loaded_latency(
                up["pings"], ramp_s, idle_ms is not None, ping_timeout)
        else:
            first = up["errors"][0] if up["errors"] else None
            result["error"] = "The upload test didn't work. " + _friendly_error(first)

        loaded = [v for v in (result["loaded_latency_down_ms"],
                              result["loaded_latency_up_ms"]) if v is not None]
        if idle_ms is not None and loaded:
            bloat = round(max(0.0, max(loaded) - idle_ms), 1)
            result["bufferbloat_ms"] = bloat
            result["bufferbloat_grade"] = bufferbloat_grade(bloat)
    except Exception as exc:  # never raise
        result["error"] = _friendly_error(exc)
    finally:
        result["duration_s"] = round(time.perf_counter() - started, 2)
        result["measured_at"] = _now_iso()
        progress(1.0, "Speed test finished." if not result.get("error")
                 else "Speed test finished with a problem.")
    return result
