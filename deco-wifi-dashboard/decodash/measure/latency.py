"""Latency ("ping") measured with TCP connects, so no admin rights are needed.

A TCP connect takes one round trip: our SYN goes out and the other side's
SYN-ACK (or a "connection refused" RST) comes back. Timing that gives a good
ping estimate. ``measure_latency()`` never raises.
"""

from __future__ import annotations

import ipaddress
import math
import socket
import statistics
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List

GATEWAY_NAME = "Your Deco"
GATEWAY_PORTS = (80, 443)
INTERNET_TARGETS = (
    ("Cloudflare", "1.1.1.1", 443),
    ("Google", "8.8.8.8", 443),
)
SAMPLE_INTERVAL_S = 0.05  # pause between samples to one target
GIVE_UP_AFTER = 3         # stop early if this many first tries all fail


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_host(host: object) -> str | None:
    """Accept "192.168.68.1", "http://192.168.68.1/", "[fe80::1]:80", ..."""
    if host is None:
        return None
    text = str(host).strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text or None


def _resolve(host: str, port: int, timeout: float = 2.0) -> str | None:
    """IP literal for host (IPv4 preferred), resolved before the timer starts.

    The lookup runs in a helper thread so a stuck DNS server can't make a
    ping wait longer than ``timeout``.
    """
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    box: Dict[str, object] = {}

    def work() -> None:
        try:
            box["infos"] = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except Exception as exc:  # noqa: BLE001 - a failed lookup is just "no answer"
            box["error"] = exc

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout)
    infos = box.get("infos")
    if thread.is_alive() or not isinstance(infos, list) or not infos:
        return None
    for family, _type, _proto, _name, sockaddr in infos:
        if family == socket.AF_INET:
            return sockaddr[0]
    return infos[0][4][0]


def _clean_timeout(value: object, default: float) -> float:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if not number > 0 or math.isinf(number):
        return default
    return number


def tcp_ping(host: str, port: int, timeout: float = 2.0) -> float | None:
    """Milliseconds for one TCP connect, or None on timeout/error.

    A refused connection still means the other side answered, so it counts.
    """
    try:
        timeout = _clean_timeout(timeout, 2.0)
        port = int(port)
        if not 0 < port < 65536:  # the OS would quietly wrap 70000 round to 4464
            return None
        name = _clean_host(host)
        if not name:
            return None
        address = _resolve(name, port, timeout)
        if not address:
            return None
        start = time.perf_counter()
        try:
            sock = socket.create_connection((address, port), timeout=timeout)
        except ConnectionRefusedError:
            return round((time.perf_counter() - start) * 1000.0, 3)
        except OSError:  # timeout, unreachable, ...
            return None
        elapsed = (time.perf_counter() - start) * 1000.0
        try:
            sock.close()
        except OSError:
            pass
        return round(elapsed, 3)
    except Exception:
        return None


def _p90(values: List[float]) -> float:
    ordered = sorted(values)
    rank = max(1, int(math.ceil(0.9 * len(ordered))))
    return ordered[rank - 1]


def _summarize(name: str, host: str, port: int, samples: List[float], sent: int) -> dict:
    ok = [float(s) for s in samples]
    failed = max(0, sent - len(ok))
    jitter = None
    if len(ok) >= 2:
        diffs = [abs(ok[i] - ok[i - 1]) for i in range(1, len(ok))]
        jitter = round(sum(diffs) / len(diffs), 2)
    return {
        "name": name,
        "host": host,
        "port": int(port),
        "samples_ms": [round(s, 2) for s in ok],
        "median_ms": round(statistics.median(ok), 2) if ok else None,
        "p90_ms": round(_p90(ok), 2) if ok else None,
        "jitter_ms": jitter,
        "loss_pct": round(failed * 100.0 / sent, 1) if sent else 100.0,
        "sent": sent,
    }


def _measure_target(name: str, host: str, port: int, count: int, timeout: float) -> dict:
    samples: List[float] = []
    sent = 0
    for i in range(count):
        if i:
            time.sleep(SAMPLE_INTERVAL_S)
        rtt = tcp_ping(host, port, timeout)
        sent += 1
        if rtt is not None:
            samples.append(rtt)
        elif not samples and sent >= GIVE_UP_AFTER:
            break  # nothing answers; don't wait for every timeout
    return _summarize(name, host, port, samples, sent)


def _measure_gateway(host: str, count: int, timeout: float) -> dict:
    result = None
    for port in GATEWAY_PORTS:
        result = _measure_target(GATEWAY_NAME, host, port, count, timeout)
        if result["samples_ms"]:
            return result
    if result is None:  # pragma: no cover - GATEWAY_PORTS is never empty
        result = _summarize(GATEWAY_NAME, host, GATEWAY_PORTS[0], [], 0)
    # Nothing answered on either port: report the first (port 80) attempt.
    result["port"] = GATEWAY_PORTS[0]
    return result


def measure_latency(gateway_host: str | None, count: int = 15, timeout: float = 2.0) -> dict:
    """LatencyResult for the Deco (gateway) and two internet servers. Never raises."""
    result: Dict[str, object] = {
        "gateway": None,
        "internet": [],
        "measured_at": _now_iso(),
        "error": None,
    }
    try:
        try:
            count = max(1, min(200, int(count)))
        except (TypeError, ValueError):
            count = 15
        timeout = _clean_timeout(timeout, 2.0)
        gateway = _clean_host(gateway_host) if gateway_host else None

        jobs = []  # (key, name, host, port)
        if gateway:
            jobs.append(("gateway", GATEWAY_NAME, gateway, GATEWAY_PORTS[0]))
        for index, (name, host, port) in enumerate(INTERNET_TARGETS):
            jobs.append((index, name, host, port))

        box: Dict[object, dict] = {}

        def work(key: object, name: str, host: str, port: int) -> None:
            try:
                if key == "gateway":
                    box[key] = _measure_gateway(host, count, timeout)
                else:
                    box[key] = _measure_target(name, host, port, count, timeout)
            except Exception:
                box[key] = _summarize(name, host, port, [], 1)

        threads = []
        for job in jobs:
            thread = threading.Thread(target=work, args=job, daemon=True)
            thread.start()
            threads.append(thread)
        limit = time.monotonic() + len(GATEWAY_PORTS) * count * (timeout + SAMPLE_INTERVAL_S) + 5.0
        for thread in threads:
            thread.join(max(0.0, limit - time.monotonic()))

        def get(key: object, name: str, host: str, port: int) -> dict:
            found = box.get(key)
            return found if found is not None else _summarize(name, host, port, [], 1)

        if gateway:
            result["gateway"] = get("gateway", GATEWAY_NAME, gateway, GATEWAY_PORTS[0])
        result["internet"] = [
            get(index, name, host, port) for index, (name, host, port) in enumerate(INTERNET_TARGETS)
        ]

        internet_ok = any(t["samples_ms"] for t in result["internet"])  # type: ignore[index]
        gw = result["gateway"]
        gateway_ok = bool(gw and gw["samples_ms"])  # type: ignore[index]
        if not internet_ok and gw is not None and not gateway_ok:
            result["error"] = ("Couldn't reach your Deco or the internet. Check that this "
                               "computer is connected to your network.")
        elif not internet_ok:
            result["error"] = ("Couldn't reach the internet test servers (Cloudflare and "
                               "Google). Your internet connection may be down.")
        elif gw is not None and not gateway_ok:
            result["error"] = ("Your Deco didn't answer on port 80 or 443, so its ping "
                               "couldn't be measured.")
    except Exception as exc:  # never raise
        result["error"] = "The latency test hit a problem: %s" % (exc,)
    result["measured_at"] = _now_iso()
    return result
