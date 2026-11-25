"""Local web server for the Deco Wi-Fi Dashboard.

* Binds to 127.0.0.1 only and checks the ``Host`` header (this blocks
  "DNS rebinding" tricks from websites).
* Every ``/api/*`` call needs the per-run random token in ``X-Dash-Token``.
  The token is put into ``index.html`` when the page is served.
* The Deco password lives only inside the in-memory ``DecoClient``. It is never
  written to disk, logged, or sent back to the browser.
* Measurements run in background threads ("jobs"), one per job name at a time.

See SPEC.md, section "Server HTTP API", for the endpoints.
"""

from __future__ import annotations

import copy
import errno
import hmac
import http.server
import importlib
import ipaddress
import json
import math
import os
import re
import secrets
import signal
import statistics
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

__all__ = [
    "HISTORY_PATH",
    "JOB_NAMES",
    "ApiError",
    "DashState",
    "DashServer",
    "DashHandler",
    "make_server",
    "serve",
    "validate_host",
    "match_node_name",
    "build_room_test",
    "load_history",
    "save_history",
    "current_history_path",
]

DEFAULT_PORT = 8765
DEFAULT_DECO_HOST = "192.168.68.1"
WEB_DIR = Path(__file__).resolve().parent / "web"
JOB_NAMES = ("deco", "link", "latency", "speed", "dns", "room")
RUN_GROUPS = {
    "deco": ("deco",),
    "link": ("link",),
    "latency": ("latency",),
    "speed": ("speed",),
    "dns": ("dns",),
    "quick": ("deco", "link", "latency", "dns"),
    "all": ("deco", "link", "latency", "dns", "speed"),
}
ROOM_JOBS = ("room", "link", "latency", "speed")
MAX_BODY_BYTES = 64 * 1024
MAX_HISTORY = 100
MAX_ROOM_NAME = 60
MAX_PASSWORD = 512
TOKEN_PLACEHOLDER = "__DASH_TOKEN__"

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
}

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'none'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)

ROOM_TEST_KEYS = ("room", "at", "down_mbps", "up_mbps", "latency_ms", "gateway_latency_ms",
                  "rssi_dbm", "band", "width_mhz", "phy", "bssid", "node_name")

_STEP_START = {
    "deco": "Reading your Deco…",
    "link": "Checking this computer's connection…",
    "latency": "Measuring latency (ping)…",
    "speed": "Starting the speed test…",
    "dns": "Timing DNS lookups…",
    "room": "Starting the room test…",
}
_WAITING = "Waiting for the other tests to finish…"


def _home_dir() -> Path:
    env = os.environ.get("DECODASH_HOME")
    if env and env.strip():
        return Path(env.strip()).expanduser()
    try:
        return Path.home() / ".decodash"
    except Exception:  # no home directory (very unusual)
        return Path.cwd() / ".decodash"


#: Where room tests are saved. ``$DECODASH_HOME`` overrides ``~/.decodash``.
HISTORY_PATH = _home_dir() / "history.json"


def current_history_path() -> Path:
    """HISTORY_PATH, re-reading ``$DECODASH_HOME`` in case it changed after import."""
    env = os.environ.get("DECODASH_HOME")
    if env and env.strip():
        return Path(env.strip()).expanduser() / "history.json"
    return HISTORY_PATH


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

class ApiError(Exception):
    """An error that becomes ``{"error": message}`` with an HTTP status."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class JobError(Exception):
    """A job failed with a message that is safe and friendly to show."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _log(message: str) -> None:
    try:
        sys.stderr.write("[decodash] %s\n" % message)
        sys.stderr.flush()
    except Exception:
        pass


def _json_safe(obj, depth: int = 0):
    """Plain JSON types only; NaN/inf become None (JSON can't hold them)."""
    if depth > 60:
        return None
    if obj is None or isinstance(obj, (bool, str)):
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {str(k): _json_safe(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_json_safe(v, depth + 1) for v in obj]
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)


def _json_bytes(obj) -> bytes:
    return json.dumps(_json_safe(obj), ensure_ascii=False, allow_nan=False).encode("utf-8")


# Keep these in step with deco_client._SECRET_PARTS / _SECRET_EXACT / _SECRET_WORDS
# (tests/test_integration.py checks that they match).
_SECRET_PARTS = ("password", "passwd", "psk", "secret", "token", "stok", "sysauth",
                 "wpa", "passphrase", "pwd", "credential")
_SECRET_EXACT = frozenset({"key", "pin", "pass", "pw"})
_SECRET_WORDS = frozenset({"key", "pass", "pin", "pw", "pwd", "psk", "cookie", "apikey", "privkey"})
_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")


def _local_is_secret(key) -> bool:
    if not isinstance(key, str) or not key:
        return False
    lk = key.lower()
    if lk in _SECRET_EXACT or lk.endswith("_key") or lk.endswith("_pin"):
        return True
    if any(p in lk for p in _SECRET_PARTS):
        return True
    return any(word.lower() in _SECRET_WORDS for word in _WORD_RE.findall(key))


def _local_redact(obj):
    """Fallback for deco_client.redact (same rules)."""
    if isinstance(obj, dict):
        return {k: ("***" if _local_is_secret(k) else _local_redact(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_local_redact(v) for v in obj]
    return copy.deepcopy(obj)


def _redact(obj):
    try:
        from .deco_client import redact
    except Exception:
        return _local_redact(obj)
    try:
        return redact(obj)
    except Exception:
        return _local_redact(obj)


def _deco_module():
    """The deco_client module (a function so tests can swap it)."""
    from . import deco_client
    return deco_client


def _analyze_func():
    """analyze.analyze (a function so tests can swap it)."""
    from .analyze import analyze
    return analyze


def _measure_module(name: str):
    return importlib.import_module("%s.measure.%s" % (__package__ or "decodash", name))


def _demo_module():
    from . import demo_data
    return demo_data


_HOST_RE = re.compile(r"^(?:(https?)://)?(\[[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]{1,32})?\]|[A-Za-z0-9.-]+)"
                      r"(?::(\d{1,5}))?/?$", re.IGNORECASE)
_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_host(value) -> str:
    """Check a Deco address typed by the user and return a clean version.

    Accepts an IP address or a host name, optionally with ``http://`` or
    ``https://`` and a port. Anything else (paths, spaces, user names, other
    schemes) raises ``ApiError(400)``.
    """
    bad = ApiError(400, "That doesn't look like a Deco address. Type just the numbers, "
                        "like 192.168.68.1.")
    if not isinstance(value, str):
        raise bad
    text = value.strip()
    if not text or len(text) > 270:
        raise bad
    # A bare IPv6 address ("fe80::1", "fe80::1%en0") needs [brackets] to be read
    # like DecoClient reads it. No port is allowed without brackets (ambiguous).
    scheme_part, sep, rest = text.rpartition("://")
    rest_no_slash = rest[:-1] if rest.endswith("/") else rest
    if rest_no_slash.count(":") >= 2 and not rest_no_slash.startswith("["):
        try:
            if ipaddress.ip_address(rest_no_slash).version == 6:
                text = scheme_part + sep + "[" + rest_no_slash + "]"
        except ValueError:
            pass
    m = _HOST_RE.match(text)
    if not m:
        raise bad
    scheme, host, port = m.group(1), m.group(2), m.group(3)
    bare = host[1:-1] if host.startswith("[") else host
    ip = None
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_unspecified or ip.is_multicast or (ip.version == 4 and str(ip) == "255.255.255.255"):
            raise bad
        host_out = "[%s]" % ip.compressed if ip.version == 6 else str(ip)
    else:
        if host.startswith("["):
            raise bad
        name = bare.rstrip(".").lower()
        labels = name.split(".")
        if (not name or len(name) > 253 or not all(_LABEL_RE.match(lbl) for lbl in labels)
                or not re.search(r"[a-z]", name)):
            raise bad
        host_out = name
    if port is not None:
        port_num = int(port)
        if not 0 < port_num < 65536:
            raise bad
        host_out = "%s:%d" % (host_out, port_num)
    if scheme:
        return "%s://%s" % (scheme.lower(), host_out)
    return host_out


def _host_only(host: str | None) -> str | None:
    """'http://192.168.68.1:80' -> '192.168.68.1'."""
    if not host or not isinstance(host, str):
        return None
    text = host.strip()
    if "://" not in text:
        text = "http://" + text
    try:
        return urllib.parse.urlsplit(text).hostname
    except ValueError:
        return None


def _mac_hex(value) -> str | None:
    if not isinstance(value, str):
        return None
    hexdigits = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(hexdigits) != 12 or len(re.sub(r"[0-9A-Fa-f:\-. ]", "", value)) != 0:
        return None
    return hexdigits.upper()


def _mac_family(hexmac: str) -> str:
    """First 11 hex digits, with the 'locally administered' bit cleared.

    Deco BSSIDs differ slightly per band (usually only the last hex digit, on
    some models also that bit in the first byte), so this lets us match a
    BSSID to the Deco it belongs to.
    """
    first = int(hexmac[:2], 16) & ~0x02
    return "%02X%s" % (first, hexmac[2:11])


def match_node_name(bssid, nodes) -> str | None:
    """Name of the Deco whose MAC/BSSID matches ``bssid`` (or None)."""
    target = _mac_hex(bssid)
    if not target or not isinstance(nodes, list):
        return None
    candidates = []  # (node name, hex mac)
    for node in nodes:
        if not isinstance(node, dict):
            continue
        name = node.get("name")
        if not isinstance(name, str) or not name:
            continue
        macs = [node.get("mac")]
        bssids = node.get("bssids")
        if isinstance(bssids, dict):
            macs.extend(bssids.values())
        elif isinstance(bssids, list):
            macs.extend(bssids)
        for mac in macs:
            hexmac = _mac_hex(mac)
            if hexmac:
                candidates.append((name, hexmac))
    for name, hexmac in candidates:
        if hexmac == target:
            return name
    family = _mac_family(target)
    best = None
    best_gap = None
    for name, hexmac in candidates:
        if _mac_family(hexmac) == family:
            gap = abs(int(hexmac, 16) - int(target, 16))
            if best_gap is None or gap < best_gap:
                best, best_gap = name, gap
    return best


def _num(value) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        f = float(value)
        return f if math.isfinite(f) else None
    return None


def _int_or_none(value) -> int | None:
    f = _num(value)
    return int(round(f)) if f is not None else None


def _str_or_none(value, limit: int = 120) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text[:limit] if text else None


def _internet_median(latency) -> float | None:
    if not isinstance(latency, dict):
        return None
    medians = []
    for target in latency.get("internet") or []:
        if isinstance(target, dict):
            m = _num(target.get("median_ms"))
            if m is not None:
                medians.append(m)
    if not medians:
        return None
    return round(statistics.median(medians), 2)


def build_room_test(room: str, link, latency, speed, nodes=None, at: str | None = None) -> dict:
    """A RoomTest dict from fresh measurements (any of them may be None)."""
    link = link if isinstance(link, dict) else {}
    speed = speed if isinstance(speed, dict) else {}
    gateway = latency.get("gateway") if isinstance(latency, dict) else None
    gw_ms = _num(gateway.get("median_ms")) if isinstance(gateway, dict) else None
    bssid = _str_or_none(link.get("bssid"), 40)
    return {
        "room": room,
        "at": at or _now_iso(),
        "down_mbps": _num(speed.get("down_mbps")),
        "up_mbps": _num(speed.get("up_mbps")),
        "latency_ms": _internet_median(latency),
        "gateway_latency_ms": gw_ms,
        "rssi_dbm": _int_or_none(link.get("rssi_dbm")),
        "band": _str_or_none(link.get("band"), 20),
        "width_mhz": _int_or_none(link.get("width_mhz")),
        "phy": _str_or_none(link.get("phy"), 40),
        "bssid": bssid,
        "node_name": match_node_name(bssid, nodes or []),
    }


def _clean_room(value) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ApiError(400, "The room name has to be text.")
    text = "".join(ch for ch in value if ch.isprintable())
    text = " ".join(text.split())
    return text[:MAX_ROOM_NAME] or None


def _sanitize_room_test(entry) -> dict | None:
    if not isinstance(entry, dict):
        return None
    room = entry.get("room")
    if not isinstance(room, str) or not room.strip():
        return None
    out = {
        "room": " ".join(room.split())[:MAX_ROOM_NAME],
        "at": _str_or_none(entry.get("at"), 40),
        "down_mbps": _num(entry.get("down_mbps")),
        "up_mbps": _num(entry.get("up_mbps")),
        "latency_ms": _num(entry.get("latency_ms")),
        "gateway_latency_ms": _num(entry.get("gateway_latency_ms")),
        "rssi_dbm": _int_or_none(entry.get("rssi_dbm")),
        "band": _str_or_none(entry.get("band"), 20),
        "width_mhz": _int_or_none(entry.get("width_mhz")),
        "phy": _str_or_none(entry.get("phy"), 40),
        "bssid": _str_or_none(entry.get("bssid"), 40),
        "node_name": _str_or_none(entry.get("node_name"), 80),
    }
    return out


def _atomic_write_json(path: Path, data) -> None:
    path = Path(path)
    created = not path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if created:
        # Only lock down a folder we made ourselves. $DECODASH_HOME may point at an
        # existing folder (even $HOME or /tmp), and changing that would break things.
        try:
            os.chmod(str(path.parent), 0o700)
        except OSError:
            pass
    fd, tmp = tempfile.mkstemp(prefix=".%s." % path.name, suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(_json_safe(data), fh, indent=2, ensure_ascii=False, allow_nan=False)
            fh.write("\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_history(path) -> list:
    """Room tests from ``path`` (newest last). A missing or broken file gives []."""
    path = Path(path)
    try:
        with open(str(path), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as err:
        _log("Couldn't read the saved room tests (%s). Starting with an empty list." % type(err).__name__)
        try:
            backup = path.with_name(path.name + ".broken-%d" % int(time.time()))
            os.replace(str(path), str(backup))
            _log("The old file was kept as %s." % backup.name)
        except OSError:
            pass
        return []
    if isinstance(data, dict):
        data = data.get("history")
    if not isinstance(data, list):
        return []
    out = [e for e in (_sanitize_room_test(x) for x in data) if e]
    return out[-MAX_HISTORY:]


def save_history(path, history: list) -> None:
    """Atomically save the newest MAX_HISTORY room tests."""
    _atomic_write_json(Path(path), list(history)[-MAX_HISTORY:])


def _load_settings(path: Path) -> dict:
    try:
        with open(str(path), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _plan_value(value, label: str) -> float | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool):
        raise ApiError(400, "Your %s plan speed has to be a number." % label)
    if isinstance(value, str):
        try:
            value = float(value.strip())
        except ValueError:
            raise ApiError(400, "Your %s plan speed has to be a number, like 500." % label) from None
    f = _num(value)
    if f is None:
        raise ApiError(400, "Your %s plan speed has to be a number, like 500." % label)
    if f == 0:
        return None
    if f < 0 or f > 100000:
        raise ApiError(400, "Your %s plan speed should be between 1 and 100000 Mbps." % label)
    return round(f, 2)


def _empty_snapshot(deco_host: str) -> dict:
    return {
        "generated_at": _now_iso(),
        "demo": False,
        "settings": {
            "deco_host": deco_host,
            "plan_down_mbps": None,
            "plan_up_mbps": None,
            "room": None,
        },
        "deco": None,
        "deco_error": None,
        "link": None,
        "latency": None,
        "speed": None,
        "dns": None,
        "history": [],
    }


def _idle_job() -> dict:
    return {"status": "idle", "progress": 0.0, "message": ""}


def _coverage(snapshot: dict) -> dict:
    """Same meaning as analyze()'s data_coverage: True only when there are usable numbers."""
    def part(key: str) -> dict:
        value = snapshot.get(key)
        return value if isinstance(value, dict) else {}

    history = snapshot.get("history") if isinstance(snapshot.get("history"), list) else []
    rooms = {str(e.get("room")).strip().lower() for e in history if isinstance(e, dict) and e.get("room")}
    link, latency, speed = part("link"), part("latency"), part("speed")
    gateway = latency.get("gateway") if isinstance(latency.get("gateway"), dict) else {}
    medians = [gateway.get("median_ms")] + [t.get("median_ms") for t in (latency.get("internet") or [])
                                            if isinstance(t, dict)]
    return {
        "deco": isinstance(snapshot.get("deco"), dict),
        "link": link.get("type") in ("wifi", "ethernet") or _num(link.get("rssi_dbm")) is not None,
        "latency": any(_num(m) is not None for m in medians),
        "speed": _num(speed.get("down_mbps")) is not None or _num(speed.get("up_mbps")) is not None,
        "dns": _num(part("dns").get("median_ms")) is not None,
        "rooms": len(rooms),
    }


def _fallback_analysis(snapshot: dict, note: str) -> dict:
    return {
        "score": None,
        "grade": None,
        "headline": "We couldn't work out your score this time, but your measurements are still shown below.",
        "bottleneck": "not enough data",
        "findings": [],
        "checklist": [],
        "data_coverage": _coverage(snapshot),
        "error": note,
    }


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class DashState:
    """Everything the server knows. All access goes through ``self.lock``."""

    def __init__(self, demo: bool = False, deco_host: str = DEFAULT_DECO_HOST,
                 history_path=None, demo_delay: float = 1.0) -> None:
        self.lock = threading.RLock()
        # Serialises "copy, then write the file" so an older copy can never land on
        # disk after a newer one (e.g. a room test saving while history is cleared).
        self._io_lock = threading.Lock()
        self.demo = bool(demo)
        self.demo_delay = max(0.0, float(demo_delay))
        self.client = None          # DecoClient, in memory only
        self.demo_connected = self.demo
        self.jobs = {name: _idle_job() for name in JOB_NAMES}
        real_history = Path(history_path) if history_path else current_history_path()
        self.real_history_path = real_history
        # Demo room tests go to their own file so fake rooms never mix with real ones.
        self.history_path = real_history.with_name("demo-history.json") if self.demo else real_history
        self.settings_path = real_history.with_name("settings.json")

        try:
            host = validate_host(deco_host)
        except ApiError:
            _log("Ignoring the Deco address %r because it doesn't look valid." % (deco_host,))
            host = DEFAULT_DECO_HOST

        if self.demo:
            self.snapshot = _demo_module().build_demo_snapshot()
            saved = load_history(self.history_path)
            if saved:
                self.snapshot["history"] = saved
        else:
            self.snapshot = _empty_snapshot(host)
            self.snapshot["history"] = load_history(self.history_path)
            saved = _load_settings(self.settings_path)
            settings = self.snapshot["settings"]
            for key, label in (("plan_down_mbps", "download"), ("plan_up_mbps", "upload")):
                try:
                    settings[key] = _plan_value(saved.get(key), label)
                except ApiError:
                    pass
            try:
                settings["room"] = _clean_room(saved.get("room"))
            except ApiError:
                pass
            if host == DEFAULT_DECO_HOST and saved.get("deco_host"):
                try:
                    settings["deco_host"] = validate_host(saved.get("deco_host"))
                except ApiError:
                    pass

    # -- helpers -----------------------------------------------------------

    def _sleep(self, seconds: float) -> None:
        if self.demo_delay > 0 and seconds > 0:
            time.sleep(seconds * self.demo_delay)

    def logged_in(self) -> bool:
        with self.lock:
            return self.demo_connected if self.demo else self.client is not None

    def _save_settings(self) -> None:
        if self.demo:
            return
        with self._io_lock:
            with self.lock:
                data = dict(self.snapshot["settings"])
            try:
                _atomic_write_json(self.settings_path, data)
            except OSError as err:
                _log("Couldn't save settings (%s)." % type(err).__name__)

    def _save_history(self) -> None:
        with self._io_lock:
            with self.lock:
                history = list(self.snapshot["history"])
            try:
                save_history(self.history_path, history)
            except OSError as err:
                _log("Couldn't save the room tests (%s)." % type(err).__name__)

    def _set_job(self, name: str, status: str, progress: float | None = None,
                 message: str | None = None) -> None:
        with self.lock:
            job = self.jobs[name]
            job["status"] = status
            if progress is not None:
                job["progress"] = max(0.0, min(1.0, float(progress)))
            if message is not None:
                job["message"] = str(message)[:300]

    def _progress(self, name: str, fraction, message=None) -> None:
        try:
            frac = float(fraction)
        except (TypeError, ValueError):
            return
        if not math.isfinite(frac):
            return
        with self.lock:
            job = self.jobs[name]
            if job["status"] != "running":
                return
            job["progress"] = max(0.0, min(1.0, frac))
            if isinstance(message, str) and message:
                job["message"] = message[:300]

    def _claim(self, names, all_or_nothing: bool = False) -> list:
        """Mark free jobs as running (waiting). Returns the names claimed."""
        with self.lock:
            free = [n for n in names if self.jobs[n]["status"] != "running"]
            if all_or_nothing and len(free) != len(names):
                return []
            for n in free:
                self.jobs[n] = {"status": "running", "progress": 0.0, "message": _WAITING}
            return free

    def _start_thread(self, target, args, names) -> None:
        thread = threading.Thread(target=target, args=args, daemon=True,
                                  name="decodash-" + "-".join(names))
        try:
            thread.start()
        except RuntimeError:
            for n in names:
                self._set_job(n, "error", 0.0, "Couldn't start this test. Try again.")

    # -- payloads ----------------------------------------------------------

    def _snapshot_copy(self) -> dict:
        with self.lock:
            snap = copy.deepcopy(self.snapshot)
        snap["generated_at"] = _now_iso()
        return _redact(snap)

    @staticmethod
    def _analysis(snap: dict) -> dict:
        try:
            analyze = _analyze_func()
            result = analyze(copy.deepcopy(snap))
            if not isinstance(result, dict):
                raise TypeError("analyze() returned %s, not a dict" % type(result).__name__)
            return result
        except Exception as err:
            return _fallback_analysis(snap, "The analysis part hit a problem (%s: %s)."
                                      % (type(err).__name__, str(err)[:200]))

    def state_payload(self) -> dict:
        snap = self._snapshot_copy()
        with self.lock:
            jobs = copy.deepcopy(self.jobs)
            logged_in = self.logged_in()
        deco = snap.get("deco") if isinstance(snap.get("deco"), dict) else {}
        link = snap.get("link") if isinstance(snap.get("link"), dict) else {}
        return {
            "snapshot": snap,
            "analysis": self._analysis(snap),
            "jobs": jobs,
            "logged_in": logged_in,
            "demo": self.demo,
            "version": __version__,
            # optional extra: which Deco this computer is connected to, if we can tell
            "link_node_name": match_node_name(link.get("bssid"), deco.get("nodes") or []),
        }

    def export_payload(self) -> dict:
        snap = self._snapshot_copy()
        return {
            "app": "Deco Wi-Fi Dashboard",
            "version": __version__,
            "exported_at": _now_iso(),
            "demo": self.demo,
            "note": "Passwords and other secrets are removed from this file.",
            "snapshot": snap,
            "analysis": self._analysis(snap),
        }

    # -- Deco login / logout -----------------------------------------------

    def login(self, host_value, password) -> None:
        host = validate_host(host_value)
        if not isinstance(password, str) or not password:
            raise ApiError(400, "Type your Deco owner password first.")
        if len(password) > MAX_PASSWORD:
            raise ApiError(400, "That password is too long.")

        with self.lock:
            if self.jobs["deco"]["status"] == "running":
                raise ApiError(409, "Already talking to the Deco. Wait a few seconds and try again.")
            self.jobs["deco"] = {"status": "running", "progress": 0.1, "message": "Logging in to your Deco…"}
            old = self.client
            self.client = None

        if self.demo:
            # Nothing is sent anywhere in demo mode, and the password is dropped.
            self._sleep(0.4)
            with self.lock:
                self.demo_connected = True
                self.snapshot["settings"]["deco_host"] = host
            self._set_job("deco", "done", 1.0, "Connected (demo: nothing was sent anywhere).")
            return

        if old is not None:
            self._safe_logout(old)

        mod = None
        client = None
        try:
            mod = _deco_module()
            client = mod.DecoClient(host, password)
            self._progress("deco", 0.4, "Logged in. Reading your Deco…")
            data = client.fetch_all()
            if not isinstance(data, dict):
                raise TypeError("fetch_all() returned %s" % type(data).__name__)
        except Exception as err:
            if client is not None:
                self._safe_logout(client)
            status, message = self._login_error(err, mod, password)
            with self.lock:
                self.snapshot["deco_error"] = message
            self._set_job("deco", "error", 1.0, message)
            raise ApiError(status, message) from None
        finally:
            password = None  # noqa: F841 (drop our reference as early as possible)

        with self.lock:
            self.client = client
            self.snapshot["deco"] = data
            self.snapshot["deco_error"] = None
            self.snapshot["settings"]["deco_host"] = host
        self._set_job("deco", "done", 1.0, self._deco_summary(data))
        self._save_settings()

    @staticmethod
    def _login_error(err: Exception, mod, password: str | None):
        def is_a(name: str) -> bool:
            value = getattr(mod, name, None) if mod is not None else None
            return isinstance(value, type) and isinstance(err, value)

        text = str(err).strip()
        if password and password in text:
            text = text.replace(password, "***")
        if is_a("DecoAuthError"):
            return 401, text or ("The Deco didn't accept that password. Use the owner password "
                                 "(the TP-Link ID password you use in the Deco app).")
        if is_a("DecoUnsupportedFirmware"):
            return 400, text or ("Your Deco's firmware uses an older login that this tool can't "
                                 "do yet. Update the firmware in the Deco app and try again.")
        if is_a("DecoConnectionError"):
            return 502, text or ("Couldn't reach your Deco. Check that this computer is on your "
                                 "home Wi-Fi and the address is right (often 192.168.68.1).")
        if is_a("DecoError"):
            return 502, text or "The Deco answered with something we didn't expect. Try again in a minute."
        _log("Login failed with an unexpected %s." % type(err).__name__)
        return 500, ("Something unexpected went wrong while talking to the Deco (%s). "
                     "Try again, and if it keeps happening, restart the dashboard." % type(err).__name__)

    @staticmethod
    def _safe_logout(client) -> None:
        try:
            client.logout()
        except Exception:
            pass

    def logout(self) -> None:
        with self.lock:
            client = self.client
            self.client = None
            if self.demo:
                self.demo_connected = False
        if client is not None:
            self._safe_logout(client)

    def close(self) -> bool:
        """Log out of the Deco (used on shutdown). True if we were logged in."""
        with self.lock:
            client = self.client
            self.client = None
        if client is None:
            return False
        self._safe_logout(client)
        return True

    @staticmethod
    def _deco_summary(data: dict) -> str:
        nodes = data.get("nodes") if isinstance(data.get("nodes"), list) else []
        clients = data.get("clients") if isinstance(data.get("clients"), list) else []
        online = [c for c in clients if isinstance(c, dict) and c.get("online", True)]
        msg = "Read %d Deco%s and %d device%s." % (
            len(nodes), "" if len(nodes) == 1 else "s", len(online), "" if len(online) == 1 else "s")
        errors = data.get("errors") if isinstance(data.get("errors"), dict) else {}
        if errors:
            msg += " Some parts couldn't be read (%s)." % ", ".join(sorted(str(k) for k in errors))
        return msg

    # -- settings / history ------------------------------------------------

    def update_settings(self, body: dict) -> None:
        changes = {}
        if "plan_down_mbps" in body:
            changes["plan_down_mbps"] = _plan_value(body.get("plan_down_mbps"), "download")
        if "plan_up_mbps" in body:
            changes["plan_up_mbps"] = _plan_value(body.get("plan_up_mbps"), "upload")
        if "room" in body:
            changes["room"] = _clean_room(body.get("room"))
        if "deco_host" in body and body.get("deco_host") not in (None, ""):
            changes["deco_host"] = validate_host(body.get("deco_host"))
        with self.lock:
            self.snapshot["settings"].update(changes)
        self._save_settings()

    def clear_history(self) -> None:
        with self.lock:
            self.snapshot["history"] = []
        self._save_history()

    # -- jobs --------------------------------------------------------------

    def run(self, what) -> None:
        if not isinstance(what, str) or what not in RUN_GROUPS:
            raise ApiError(400, "Unknown test. Use one of: %s." % ", ".join(sorted(RUN_GROUPS)))
        names = list(RUN_GROUPS[what])
        if "deco" in names and not self.logged_in():
            if what == "deco":
                raise ApiError(400, "Connect to your Deco first (in the 'Connect to Deco' card).")
            names.remove("deco")
            with self.lock:
                if self.jobs["deco"]["status"] != "running":
                    self.jobs["deco"] = {"status": "idle", "progress": 0.0,
                                         "message": "Skipped: connect to your Deco to include it."}
        claimed = self._claim(names)
        if "deco" in claimed:
            self._start_thread(self._run_chain, (["deco"],), ["deco"])
        chain = [n for n in names if n in claimed and n != "deco"]
        if chain:
            self._start_thread(self._run_chain, (chain,), chain)

    def room_test(self, room_value) -> str:
        room = _clean_room(room_value) if room_value is not None else None
        if not room:
            with self.lock:
                room = self.snapshot["settings"].get("room")
        if not room:
            raise ApiError(400, "Type the name of the room you're in first.")
        if not self._claim(ROOM_JOBS, all_or_nothing=True):
            raise ApiError(409, "A test is already running. Wait for it to finish, then try again.")
        with self.lock:
            self.snapshot["settings"]["room"] = room
            self.jobs["room"]["message"] = _STEP_START["room"]
        self._save_settings()
        self._start_thread(self._room_worker, (room,), list(ROOM_JOBS))
        return room

    def _run_chain(self, names) -> None:
        for name in names:
            self._execute(name)

    def _execute(self, name: str, room: str | None = None, extra_cb=None):
        """Run one measurement as job ``name``. Returns the fresh result or None."""
        def progress(fraction, message=None):
            self._progress(name, fraction, message)
            if extra_cb is not None:
                try:
                    extra_cb(fraction, message)
                except Exception:
                    pass

        self._set_job(name, "running", 0.0, _STEP_START.get(name, "Working…"))
        try:
            result = self._measure(name, progress, room)
            status, message = self._store(name, result)
        except JobError as err:
            self._set_job(name, "error", 1.0, str(err))
            return None
        except Exception as err:
            _log("The %s test failed: %s\n%s" % (name, type(err).__name__, traceback.format_exc()))
            self._set_job(name, "error", 1.0,
                          "Something went wrong in this test (%s). Try again." % type(err).__name__)
            return None
        self._set_job(name, status, 1.0, message)
        return result

    def _measure(self, name: str, progress, room: str | None):
        if self.demo:
            demo = _demo_module()
            sleep = self._sleep
            if not room:
                with self.lock:
                    room = self.snapshot["settings"].get("room")
            if name == "deco":
                if not self.demo_connected:
                    raise JobError("Connect to your Deco first.")
                return demo.simulate_deco(sleep=sleep)
            if name == "link":
                return demo.simulate_link(room, sleep=sleep)
            if name == "latency":
                return demo.simulate_latency(room, sleep=sleep)
            if name == "dns":
                return demo.simulate_dns(sleep=sleep)
            if name == "speed":
                return demo.simulate_speed(room, progress_cb=progress, sleep=sleep)
            raise JobError("Unknown test.")

        if name == "deco":
            with self.lock:
                client = self.client
            if client is None:
                raise JobError("Connect to your Deco first.")
            progress(0.2, "Reading your Deco…")
            mod = _deco_module()
            base = getattr(mod, "DecoError", None)
            try:
                return client.fetch_all()
            except Exception as err:
                if isinstance(base, type) and isinstance(err, base):
                    message = str(err) or "Couldn't read the Deco."
                    with self.lock:
                        self.snapshot["deco_error"] = message
                    raise JobError(message) from None
                raise
        if name == "link":
            return _measure_module("wifi_link").get_link_info()
        if name == "latency":
            return _measure_module("latency").measure_latency(self._gateway_host())
        if name == "dns":
            return _measure_module("dns_check").measure_dns()
        if name == "speed":
            return _measure_module("speedtest").run_speedtest(progress_cb=progress)
        raise JobError("Unknown test.")

    def _gateway_host(self) -> str | None:
        with self.lock:
            client = self.client
            setting = self.snapshot["settings"].get("deco_host")
        host = getattr(client, "host", None) if client is not None else None
        if not host:
            try:
                host = _measure_module("wifi_link").default_gateway()
            except Exception:
                host = None
        if not host:
            host = _host_only(setting)
        return host

    def _store(self, name: str, result):
        """Save a fresh result into the snapshot. Returns (job status, message)."""
        if not isinstance(result, dict):
            raise JobError("The test didn't return any data.")
        error = result.get("error") if isinstance(result.get("error"), str) else None

        if name == "deco":
            with self.lock:
                self.snapshot["deco"] = result
                self.snapshot["deco_error"] = None
            return "done", self._deco_summary(result)

        if name == "link":
            with self.lock:
                self.snapshot["link"] = result
            if result.get("type") == "ethernet":
                return "done", "You're on a cable (Ethernet), not Wi-Fi."
            if result.get("type") != "wifi" and error:
                return "error", error
            bits = []
            band = result.get("band")
            if band:
                bits.append(str(band).replace("GHz", " GHz"))
            if _num(result.get("rssi_dbm")) is not None:
                bits.append("%d dBm" % int(result["rssi_dbm"]))
            if _num(result.get("width_mhz")) is not None:
                bits.append("%d MHz wide" % int(result["width_mhz"]))
            return "done", ("Wi-Fi: " + ", ".join(bits) + ".") if bits else (error or "Done.")

        if name == "latency":
            with self.lock:
                self.snapshot["latency"] = result
            internet = _internet_median(result)
            gateway = result.get("gateway") if isinstance(result.get("gateway"), dict) else None
            gw = _num(gateway.get("median_ms")) if gateway else None
            if internet is None and gw is None:
                return "error", error or "No replies. Check that you're online."
            bits = []
            if gw is not None:
                bits.append("Deco %.0f ms" % gw)
            if internet is not None:
                bits.append("internet %.0f ms" % internet)
            return "done", "Ping: " + ", ".join(bits) + "."

        if name == "dns":
            with self.lock:
                self.snapshot["dns"] = result
            median = _num(result.get("median_ms"))
            if median is None:
                return "error", error or "DNS lookups didn't work."
            return "done", "Websites' addresses are found in about %.0f ms." % median

        if name == "speed":
            down = _num(result.get("down_mbps"))
            up = _num(result.get("up_mbps"))
            with self.lock:
                if down is not None or up is not None or self.snapshot.get("speed") is None:
                    self.snapshot["speed"] = result
            if down is None and up is None:
                return "error", error or "The speed test didn't work. Try again in a minute."
            parts = []
            if down is not None:
                parts.append("%.0f Mbps down" % down)
            if up is not None:
                parts.append("%.0f Mbps up" % up)
            msg = ", ".join(parts) + "."
            if error:
                msg += " " + error
            return "done", msg

        raise JobError("Unknown test.")

    def _room_worker(self, room: str) -> None:
        def stage(lo: float, hi: float):
            def cb(fraction, message=None):
                try:
                    frac = lo + (hi - lo) * max(0.0, min(1.0, float(fraction)))
                except (TypeError, ValueError):
                    return
                self._progress("room", frac, message if isinstance(message, str) else None)
            return cb

        try:
            self._progress("room", 0.02, "Checking your Wi-Fi link…")
            link = self._execute("link", room, stage(0.0, 0.1))
            self._progress("room", 0.1, "Measuring latency (ping)…")
            latency = self._execute("latency", room, stage(0.1, 0.25))
            self._progress("room", 0.25, "Running the speed test…")
            speed = self._execute("speed", room, stage(0.25, 0.97))
            with self.lock:
                deco = self.snapshot.get("deco") if isinstance(self.snapshot.get("deco"), dict) else {}
                nodes = copy.deepcopy(deco.get("nodes") or [])
            entry = build_room_test(room, link, latency, speed, nodes)
            with self.lock:
                history = self.snapshot["history"]
                history.append(entry)
                if len(history) > MAX_HISTORY:
                    del history[:len(history) - MAX_HISTORY]
            self._save_history()
            bits = []
            if entry["down_mbps"] is not None:
                bits.append("%.0f Mbps down" % entry["down_mbps"])
            if entry["rssi_dbm"] is not None:
                bits.append("signal %d dBm" % entry["rssi_dbm"])
            msg = "Saved '%s'%s." % (room, (": " + ", ".join(bits)) if bits else "")
            if isinstance(link, dict) and link.get("type") == "ethernet":
                msg += " Note: you're on a cable, so this didn't test Wi-Fi."
            elif entry["down_mbps"] is None:
                msg += " The speed test part didn't work, so only the signal was saved."
            self._set_job("room", "done", 1.0, msg)
        except Exception as err:
            _log("The room test failed: %s\n%s" % (type(err).__name__, traceback.format_exc()))
            self._set_job("room", "error", 1.0,
                          "The room test hit a problem (%s). Try again." % type(err).__name__)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class DashServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    # On Windows SO_REUSEADDR would let two programs share a port, so don't.
    allow_reuse_address = os.name != "nt"

    def __init__(self, port: int, state: DashState, token: str | None = None, quiet: bool = True) -> None:
        self.state = state
        self.token = token or secrets.token_urlsafe(24)
        self.quiet = quiet
        super().__init__(("127.0.0.1", int(port)), DashHandler)

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    @property
    def url(self) -> str:
        return "http://127.0.0.1:%d/" % self.port

    def allowed_hosts(self) -> tuple:
        return ("127.0.0.1:%d" % self.port, "localhost:%d" % self.port)


class DashHandler(http.server.BaseHTTPRequestHandler):
    server_version = "decodash/" + __version__
    sys_version = ""
    timeout = 30  # seconds to send a request, so a stuck connection can't hang a thread

    # -- plumbing ------------------------------------------------------------

    def log_message(self, format, *args):  # noqa: A002 (stdlib name)
        if not getattr(self.server, "quiet", True):
            _log("%s %s" % (self.address_string(), format % args))

    def _headers_common(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    def _send(self, status: int, body: bytes, content_type: str, extra=None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._headers_common()
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _send_json(self, status: int, obj, extra=None) -> None:
        self._send(status, _json_bytes(obj), "application/json; charset=utf-8", extra)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _send_text(self, status: int, text: str) -> None:
        self._send(status, text.encode("utf-8"), "text/plain; charset=utf-8")

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        return host in self.server.allowed_hosts()

    def _origin_ok(self) -> bool:
        """If the browser says where the request came from, it must be us."""
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        origin = origin.strip().lower().rstrip("/")
        return origin in ["http://" + h for h in self.server.allowed_hosts()]

    def _token_ok(self) -> bool:
        given = self.headers.get("X-Dash-Token") or ""
        return hmac.compare_digest(given.encode("utf-8", "replace"),
                                   self.server.token.encode("utf-8"))

    def _read_json(self) -> dict:
        if self.headers.get("Transfer-Encoding"):
            raise ApiError(411, "Send the request with a Content-Length.")
        raw_len = self.headers.get("Content-Length")
        if raw_len is None or raw_len.strip() == "":
            return {}
        try:
            length = int(raw_len)
        except ValueError:
            raise ApiError(400, "Bad Content-Length.") from None
        if length < 0:
            raise ApiError(400, "Bad Content-Length.")
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            # Read (and throw away) a moderately sized body so the browser gets our
            # answer instead of a "connection reset".
            remaining = length if length <= 1024 * 1024 else 0
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            raise ApiError(413, "That request is too big.")
        data = self.rfile.read(length) if length else b""
        if not data.strip():
            return {}
        try:
            body = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ApiError(400, "The request wasn't valid JSON.") from None
        if not isinstance(body, dict):
            raise ApiError(400, "The request should be a JSON object.")
        return body

    def _path(self) -> str:
        try:
            return urllib.parse.urlsplit(self.path).path or "/"
        except ValueError:
            return ""

    # -- methods ---------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (stdlib name)
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        try:
            if not self._host_ok():
                self._send_text(403, "Forbidden: open the dashboard at the address run.py printed.")
                return
            path = self._path()
            if path.startswith("/api/"):
                self._api(method, path)
                return
            if method != "GET":
                self._send_text(405, "Method not allowed.")
                return
            if path in ("/", "/index.html", "/static/index.html"):
                self._index()
            elif path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
            elif path.startswith("/static/"):
                self._static(path[len("/static/"):])
            else:
                self._send_text(404, "Not found.")
        except ApiError as err:
            self._send_error_json(err.status, err.message)
        except Exception as err:  # never leak a stack trace to the browser
            _log("Request failed: %s\n%s" % (type(err).__name__, traceback.format_exc()))
            try:
                self._send_error_json(500, "Something went wrong inside the dashboard (%s)."
                                      % type(err).__name__)
            except Exception:
                pass

    # -- pages -------------------------------------------------------------------

    def _index(self) -> None:
        try:
            html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
        except OSError:
            self._send_text(500, "index.html is missing. Download the dashboard folder again.")
            return
        html = html.replace(TOKEN_PLACEHOLDER, self.server.token)
        self._send(200, html.encode("utf-8"), CONTENT_TYPES[".html"], {"Content-Security-Policy": CSP})

    def _static(self, raw_name: str) -> None:
        name = urllib.parse.unquote(raw_name)
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", name) or ".." in name):
            self._send_text(404, "Not found.")
            return
        ext = os.path.splitext(name)[1].lower()
        content_type = CONTENT_TYPES.get(ext)
        base = WEB_DIR.resolve()
        try:
            target = (base / name).resolve()
        except (OSError, RuntimeError):
            self._send_text(404, "Not found.")
            return
        if content_type is None or target.parent != base or not target.is_file():
            self._send_text(404, "Not found.")
            return
        try:
            body = target.read_bytes()
        except OSError:
            self._send_text(404, "Not found.")
            return
        extra = {"Content-Security-Policy": CSP} if ext == ".html" else None
        self._send(200, body, content_type, extra)

    # -- API -----------------------------------------------------------------------

    def _api(self, method: str, path: str) -> None:
        if not self._token_ok() or not self._origin_ok():
            self._send_error_json(403, "Forbidden: missing or wrong dashboard token. Reload the page.")
            return
        state: DashState = self.server.state
        get_routes = {"/api/state", "/api/export"}
        post_routes = {"/api/login", "/api/logout", "/api/settings", "/api/run",
                       "/api/room-test", "/api/history/clear"}
        if path not in get_routes and path not in post_routes:
            self._send_error_json(404, "Unknown API path.")
            return
        if (method == "GET") != (path in get_routes):
            self._send_error_json(405, "Wrong method for this API path.")
            return

        if path == "/api/state":
            self._send_json(200, state.state_payload())
            return
        if path == "/api/export":
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            self._send_json(200, state.export_payload(), {
                "Content-Disposition": 'attachment; filename="decodash-export-%s.json"' % stamp})
            return

        body = self._read_json()
        if path == "/api/login":
            password = body.get("password")
            try:
                state.login(body.get("host"), password)
            finally:
                password = None  # noqa: F841
                body.clear()
        elif path == "/api/logout":
            state.logout()
        elif path == "/api/settings":
            state.update_settings(body)
        elif path == "/api/run":
            state.run(body.get("what"))
        elif path == "/api/room-test":
            state.room_test(body.get("room"))
        elif path == "/api/history/clear":
            state.clear_history()
        self._send_json(200, state.state_payload())


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def make_server(port: int = 0, demo: bool = False, deco_host: str = DEFAULT_DECO_HOST,
                history_path=None, demo_delay: float = 1.0, quiet: bool = True) -> DashServer:
    """Build (but don't start) the server. ``port=0`` picks a free port (tests)."""
    state = DashState(demo=demo, deco_host=deco_host, history_path=history_path, demo_delay=demo_delay)
    return DashServer(port, state, quiet=quiet)


def _port_busy(err: OSError) -> bool:
    return err.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1), 10048, 10013)


def serve(port: int = DEFAULT_PORT, demo: bool = False, open_browser: bool = True,
          deco_host: str = DEFAULT_DECO_HOST) -> None:
    """Run the dashboard until Ctrl+C. Logs out of the Deco before stopping."""
    port = int(port)
    if not 0 < port < 65536:
        raise ValueError("port must be between 1 and 65535")
    server = None
    last_error = None
    for candidate in range(port, min(port + 10, 65536)):
        try:
            server = make_server(candidate, demo=demo, deco_host=deco_host)
            break
        except OSError as err:
            if not _port_busy(err):
                raise
            last_error = err
    if server is None:
        print("Port %d (and the next few) are already in use. Is the dashboard already running?\n"
              "Close the other one, or pick another port: python3 run.py --port 8800" % port)
        raise SystemExit(1) from last_error

    url = server.url
    print("")
    print("Deco Wi-Fi Dashboard %s%s" % (__version__, " (DEMO: sample data, not your network)" if demo else ""))
    if server.port != port:
        print("Port %d was busy, so it's using port %d instead." % (port, server.port))
    print("Open this in your browser:  %s" % url)
    print("It only works on this computer. Press Ctrl+C here to stop.")
    print("")
    sys.stdout.flush()

    if open_browser:
        def _open():
            try:
                webbrowser.open(url, new=2)
            except Exception:
                pass
        timer = threading.Timer(0.7, _open)
        timer.daemon = True
        timer.start()

    previous = None
    if threading.current_thread() is threading.main_thread() and hasattr(signal, "SIGTERM"):
        def _on_term(signum, frame):
            raise KeyboardInterrupt
        try:
            previous = signal.signal(signal.SIGTERM, _on_term)
        except (ValueError, OSError):
            previous = None

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        try:
            if server.state.close():
                print("Logged out of your Deco, so the Deco app on your phone works again.")
        except Exception:
            pass
        try:
            server.server_close()
        except Exception:
            pass
        if previous is not None:
            try:
                signal.signal(signal.SIGTERM, previous)
            except (ValueError, OSError):
                pass
        print("Stopped. Bye!")
