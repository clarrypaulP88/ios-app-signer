"""DNS speed: how fast this computer turns names like youtube.com into addresses.

DNS is the internet's phone book. Every new website starts with a DNS
lookup, so a slow DNS server makes everything feel laggy even when the
download speed is great. ``measure_dns()`` never raises.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import socket
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

# Popular sites: often cached nearby, so this shows the "normal" feel.
POPULAR_HOSTS = (
    "www.google.com",
    "www.youtube.com",
    "www.instagram.com",
    "www.netflix.com",
    "www.wikipedia.org",
)
# Random names under these can't be cached, so the resolver must really
# go and ask. "Name doesn't exist" is still a real answer.
UNCACHED_PARENTS = ("cloudflare.com", "google.com", "apple.com")
STOP_AFTER_TIMEOUTS = 2  # in a row: DNS is down, don't wait for every name

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _nx_codes() -> set:
    codes = set()
    for name in ("EAI_NONAME", "EAI_NODATA"):
        value = getattr(socket, name, None)
        if isinstance(value, int):
            codes.add(value)
    if sys.platform.startswith("win"):
        codes.update((11001, 11004))  # WSAHOST_NOT_FOUND, WSANO_DATA
    return codes


_NX_CODES = _nx_codes()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_timeout(value: object, default: float) -> float:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if not number > 0 or number == float("inf"):
        return default
    return number


def _random_label() -> str:
    return "q" + secrets.token_hex(7)


def _plan(hosts: list | None) -> List[Tuple[str, bool]]:
    """List of (hostname, is_uncached_lookup)."""
    if hosts:
        cleaned = []
        for host in hosts:
            if isinstance(host, str) and host.strip():
                cleaned.append((host.strip().rstrip("."), False))
        if cleaned:
            return cleaned
    plan = [(host, False) for host in POPULAR_HOSTS]
    plan.extend(("%s.%s" % (_random_label(), parent), True) for parent in UNCACHED_PARENTS)
    return plan


def _timed_lookup(host: str, timeout: float) -> Tuple[str, float | None]:
    """("ok" | "nx" | "fail" | "timeout", milliseconds or None)."""
    box: Dict[str, Any] = {}

    def work() -> None:
        start = time.perf_counter()
        try:
            socket.getaddrinfo(host, 443, 0, socket.SOCK_STREAM)
            box["status"] = "ok"
        except socket.gaierror as exc:
            box["status"] = "nx" if exc.errno in _NX_CODES else "fail"
        except Exception:
            box["status"] = "fail"
        box["ms"] = (time.perf_counter() - start) * 1000.0

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive() or "status" not in box:
        return "timeout", None
    return box["status"], box.get("ms")


# ---------------------------------------------------------------------------
# which DNS servers this computer uses
# ---------------------------------------------------------------------------

def _valid_ip(text: str) -> str | None:
    value = text.strip()
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None
    return value


def parse_resolv_conf(text: str) -> List[str]:
    """Nameserver IPs from /etc/resolv.conf text."""
    found: List[str] = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            ip = _valid_ip(parts[1])
            if ip and ip not in found:
                found.append(ip)
    return found


def parse_ipconfig_dns(text: str) -> List[str]:
    """DNS server IPs from Windows ``ipconfig /all`` (English)."""
    found: List[str] = []
    collecting = False
    for line in (text or "").splitlines():
        match = re.match(r"^\s*DNS Servers[ .]*:\s*(.*)$", line, re.I)
        if match:
            collecting = True
            ip = _valid_ip(match.group(1))
            if ip and ip not in found:
                found.append(ip)
            continue
        if collecting:
            ip = _valid_ip(line) if line.strip() else None
            if ip:
                if ip not in found:
                    found.append(ip)
                continue
            collecting = False
    return found


def _read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except Exception:
        return None


def _run(cmd: list, timeout: float) -> str | None:
    # subprocess can't take an endless (inf) or NaN timeout, so keep it sane.
    limit = max(0.2, min(_clean_timeout(timeout, 3.0), 60.0))
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, timeout=limit,
            creationflags=_NO_WINDOW, check=False,
        )
    except Exception:
        return None
    data = proc.stdout or b""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        for encoding in ("oem", "mbcs"):
            try:
                return data.decode(encoding, errors="replace")
            except LookupError:
                continue
        return data.decode("latin-1", errors="replace")


def get_resolvers(timeout: float = 3.0) -> List[str]:
    """Best-effort list of the DNS servers this computer asks. Never raises."""
    try:
        if sys.platform.startswith("win"):
            return parse_ipconfig_dns(_run(["ipconfig", "/all"], timeout) or "")
        found = parse_resolv_conf(_read_text("/etc/resolv.conf") or "")
        if found and all(ip.startswith("127.") for ip in found):
            # systemd-resolved stub: the real servers are listed here.
            upstream = parse_resolv_conf(_read_text("/run/systemd/resolve/resolv.conf") or "")
            if upstream:
                return upstream
        return found
    except Exception:
        return []


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------

_NOTES = {
    "timeout": "No answer in time.",
    "fail": "The lookup failed.",
    "skipped": "Skipped because DNS had stopped answering.",
    "nx": "Got 'name not found', but no real site worked either.",
}


def measure_dns(hosts: list | None = None, timeout: float = 3.0) -> dict:
    """DnsResult. Never raises."""
    result: Dict[str, Any] = {
        "median_ms": None,
        "samples": [],
        "resolvers": [],
        "measured_at": _now_iso(),
        "error": None,
    }
    try:
        timeout = _clean_timeout(timeout, 3.0)
        plan = _plan(hosts)
        defaults = any(uncached for _h, uncached in plan)  # the built-in host list
        try:
            result["resolvers"] = list(get_resolvers(min(timeout, 5.0)))
        except Exception:
            result["resolvers"] = []

        raw: List[Tuple[str, bool, str, float | None]] = []
        timeouts_in_row = 0
        for host, uncached in plan:
            if timeouts_in_row >= STOP_AFTER_TIMEOUTS:
                raw.append((host, uncached, "skipped", None))
                continue
            status, ms = _timed_lookup(host, timeout)
            timeouts_in_row = timeouts_in_row + 1 if status == "timeout" else 0
            raw.append((host, uncached, status, ms))

        # "Name not found" only counts as an answer if at least one real
        # lookup worked (offline Macs answer "not found" instantly).
        trusted = any(status == "ok" for _h, _u, status, _ms in raw)
        samples = []
        for host, uncached, status, ms in raw:
            ok = status == "ok" or (status == "nx" and trusted)
            sample: Dict[str, Any] = {
                "host": host,
                "ms": round(ms, 2) if ok and ms is not None else None,
                "ok": ok,
            }
            if defaults:
                sample["uncached"] = uncached
            if not ok:
                sample["note"] = _NOTES.get(status, "The lookup failed.")
            samples.append(sample)
        result["samples"] = samples

        good = [s["ms"] for s in samples if s["ok"] and s["ms"] is not None]
        result["median_ms"] = round(statistics.median(good), 2) if good else None
        uncached_ms = [s["ms"] for s in samples
                       if s.get("uncached") and s["ok"] and s["ms"] is not None]
        if uncached_ms:
            result["uncached_median_ms"] = round(statistics.median(uncached_ms), 2)
        if not good:
            if any(s for _h, _u, s, _m in raw if s in ("timeout", "skipped")):
                result["error"] = ("DNS isn't answering. DNS is the internet's phone book, "
                                   "so without it websites won't load.")
            else:
                result["error"] = ("This computer couldn't look up any website names. "
                                   "Check that it's online.")
    except Exception as exc:  # never raise
        result["error"] = "The DNS test hit a problem: %s" % (exc,)
    result["measured_at"] = _now_iso()
    return result
