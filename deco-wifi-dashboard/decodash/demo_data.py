"""Sample data for demo mode (``python3 run.py --demo``).

Everything here is made up. It describes a believable home with a Deco BE65
3-pack so people can see what the dashboard looks like before they connect
their own Deco. The snapshot is always marked ``"demo": True`` and the UI
shows a big red banner, so nobody mistakes it for their real network.

The ``simulate_*`` helpers give slightly different, realistic numbers each
time a button is pressed in demo mode. They never touch the network.
"""

from __future__ import annotations

import copy
import random
import statistics
import time
import zlib
from datetime import datetime, timedelta, timezone

__all__ = [
    "DEMO_NOTE",
    "build_demo_snapshot",
    "build_demo_deco",
    "demo_link",
    "demo_latency",
    "demo_speed",
    "demo_dns",
    "demo_history",
    "room_profile",
    "simulate_deco",
    "simulate_link",
    "simulate_latency",
    "simulate_speed",
    "simulate_dns",
]

DEMO_NOTE = "Demo mode: this is sample data for a made-up home, not your network."

BANDS = ("band2_4", "band5", "band6")

# The three Deco units (MAC addresses are invented).
MAIN_MAC = "A8:42:A1:3C:5E:80"
UPSTAIRS_MAC = "A8:42:A1:3C:61:24"
OFFICE_MAC = "A8:42:A1:3C:63:F0"

FIRMWARE = "1.1.3 Build 20250912 Rel. 61035"

PLAN_DOWN = 1000.0
PLAN_UP = 50.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).isoformat(timespec="seconds")


def _bands(b24=None, b5=None, b6=None) -> dict:
    return {"band2_4": b24, "band5": b5, "band6": b6}


def _bssid(mac: str, last: int) -> str:
    """The node MAC with its last byte replaced (Deco BSSIDs sit right next to it)."""
    return mac[:-2] + "%02X" % last


def _node_bssids(mac: str) -> dict:
    base = int(mac[-2:], 16)
    return {
        "band2_4": _bssid(mac, (base + 1) & 0xFF),
        "band5": _bssid(mac, (base + 2) & 0xFF),
        "band6": _bssid(mac, (base + 3) & 0xFF),
    }


# ---------------------------------------------------------------------------
# Deco data
# ---------------------------------------------------------------------------

def _nodes() -> list:
    main = {
        "mac": MAIN_MAC,
        "name": "Living Room",
        "model": "BE65",
        "hw_version": "1.0",
        "fw_version": FIRMWARE,
        "ip": "192.168.68.1",
        "role": "main",
        "online": True,
        "internet_online": True,
        "parent_mac": None,
        "backhaul": "n/a",
        "backhaul_bands": [],
        "signal_dbm": _bands(),
        "signal_bars": _bands(),
        "rx_rate_mbps": _bands(),
        "tx_rate_mbps": _bands(),
        "backhaul_speed_mbps": None,
        "backhaul_max_mbps": None,
        "wired_ports": 4,
        "client_count": 0,
        "bssids": _node_bssids(MAIN_MAC),
    }
    upstairs = {
        "mac": UPSTAIRS_MAC,
        "name": "Upstairs Bedroom",
        "model": "BE65",
        "hw_version": "1.0",
        "fw_version": FIRMWARE,
        "ip": "192.168.71.249",
        "role": "satellite",
        "online": True,
        "internet_online": True,
        "parent_mac": MAIN_MAC,
        "backhaul": "wireless",
        "backhaul_bands": ["band6"],
        "signal_dbm": _bands(None, None, -71),
        "signal_bars": _bands(None, None, 2),
        "rx_rate_mbps": _bands(None, None, 860.0),
        "tx_rate_mbps": _bands(None, None, 1153.0),
        "backhaul_speed_mbps": None,
        "backhaul_max_mbps": None,
        "wired_ports": 4,
        "client_count": 0,
        "bssids": _node_bssids(UPSTAIRS_MAC),
    }
    office = {
        "mac": OFFICE_MAC,
        "name": "Office",
        "model": "BE65",
        "hw_version": "1.0",
        "fw_version": FIRMWARE,
        "ip": "192.168.71.250",
        "role": "satellite",
        "online": True,
        "internet_online": True,
        "parent_mac": MAIN_MAC,
        "backhaul": "wired",
        "backhaul_bands": [],
        "signal_dbm": _bands(),
        "signal_bars": _bands(),
        "rx_rate_mbps": _bands(),
        "tx_rate_mbps": _bands(),
        "backhaul_speed_mbps": 1000.0,
        "backhaul_max_mbps": 2500.0,
        "wired_ports": 4,
        "client_count": 0,
        "bssids": _node_bssids(OFFICE_MAC),
    }
    return [main, upstairs, office]


# name, mac, ip, band, interface, node mac, down kbps, up kbps
_CLIENTS = (
    ("Sam's iPhone 16 Pro", "3C:06:30:5A:11:C2", "192.168.68.101", "band6", "main", MAIN_MAC, 2300.0, 410.0),
    ("MacBook Air", "F4:D4:88:6B:20:9E", "192.168.68.105", "band6", "main", OFFICE_MAC, 3800.0, 620.0),
    ("PS5", "BC:33:29:7E:4A:03", "192.168.68.110", "band5", "main", MAIN_MAC, 18400.0, 350.0),
    ("Samsung TV", "8C:79:F5:21:B6:4D", "192.168.68.112", "band5", "main", MAIN_MAC, 15200.0, 120.0),
    ("Mum & Dad's iPad", "A4:C3:37:90:5E:18", "192.168.68.115", "band5", "main", UPSTAIRS_MAC, 900.0, 85.0),
    ("Pixel 8", "D8:3A:DD:47:02:6F", "192.168.68.118", "band5", "main", UPSTAIRS_MAC, 340.0, 60.0),
    ("Nintendo Switch", "98:41:5C:B2:7D:31", "192.168.68.120", "band5", "main", UPSTAIRS_MAC, 12.0, 4.0),
    ("Chromecast with Google TV", "E4:F0:42:1C:93:A8", "192.168.68.122", "band5", "main", UPSTAIRS_MAC, 6100.0, 90.0),
    ("Gaming PC", "70:85:C2:3D:8E:14", "192.168.68.125", "wired", "main", OFFICE_MAC, 1250.0, 180.0),
    ("Galaxy S24", "5C:C1:D7:66:0B:F2", "192.168.68.127", "band6", "main", OFFICE_MAC, 150.0, 40.0),
    ("Apple Watch", "1C:57:DC:84:3F:7A", "192.168.68.130", "band5", "main", MAIN_MAC, 3.0, 1.0),
    ("HP LaserJet Printer", "84:69:93:C5:12:E0", "192.168.68.133", "band2_4", "main", OFFICE_MAC, 0.4, 0.2),
    ("Philips Hue Bridge", "00:17:88:A2:5D:41", "192.168.68.135", "wired", "main", MAIN_MAC, 1.2, 0.8),
    ("Smart Plug (Desk Lamp)", "50:02:91:7A:C4:0D", "192.168.68.140", "band2_4", "iot", OFFICE_MAC, 0.3, 0.1),
    ("Smart Plug (Heater)", "50:02:91:7A:D9:66", "192.168.68.141", "band2_4", "iot", UPSTAIRS_MAC, 0.3, 0.1),
    ("Ring Doorbell", "34:3E:A4:18:F7:5B", "192.168.68.143", "band2_4", "iot", MAIN_MAC, 25.0, 480.0),
    ("Echo Dot", "44:00:49:B3:6E:27", "192.168.68.145", "band2_4", "iot", MAIN_MAC, 64.0, 6.0),
    ("Roomba", "50:14:79:0C:A1:9D", "192.168.68.147", "band2_4", "iot", UPSTAIRS_MAC, 1.5, 0.9),
)


def _clients(rng: random.Random | None = None) -> list:
    names = {MAIN_MAC: "Living Room", UPSTAIRS_MAC: "Upstairs Bedroom", OFFICE_MAC: "Office"}
    out = []
    for name, mac, ip, band, iface, node, down, up in _CLIENTS:
        if rng is not None:
            down = max(0.0, down * rng.uniform(0.6, 1.4))
            up = max(0.0, up * rng.uniform(0.6, 1.4))
        out.append({
            "mac": mac,
            "name": name,
            "ip": ip,
            "online": True,
            "band": band,
            "interface": iface,
            "node_mac": node,
            "down_kbps": round(down, 1),
            "up_kbps": round(up, 1),
            # optional extra (deco_client adds it too)
            "node_name": names[node],
        })
    return out


def _band_cfg(channel, width, width_mhz, backhaul_channel) -> dict:
    return {
        "enabled": True,
        "channel": channel,
        "channel_width": width,
        "width_mhz": width_mhz,
        "mode": "11be",
        "backhaul_channel": backhaul_channel,
        "hidden": False,
    }


def _wifi() -> dict:
    return {
        "bands": {
            "band2_4": _band_cfg(6, "HT40", 40, 6),
            "band5": _band_cfg(36, "EHT160", 160, 36),
            "band6": _band_cfg(37, "EHT320", 320, 37),
        },
        "guest_enabled": False,
        "iot_enabled": True,
        "mlo_enabled": False,
        "same_ssid_all_bands": True,
    }


def _wan() -> dict:
    return {
        "wan_ip": "192.168.1.20",
        "wan_mask": "255.255.255.0",
        "gateway": "192.168.1.1",
        "dial_type": "dynamic_ip",
        "dns": ["192.168.1.1"],
        "auto_dns": True,
        "lan_ip": "192.168.68.1",
        "lan_mask": "255.255.252.0",
        "double_nat": True,
        "cgnat": False,
        "ipv6_enabled": False,
    }


def build_demo_deco(rng: random.Random | None = None) -> dict:
    """DecoData for the made-up BE65 3-pack."""
    nodes = _nodes()
    clients = _clients(rng)
    counts = {}
    for c in clients:
        if c["online"] and c["node_mac"]:
            counts[c["node_mac"]] = counts.get(c["node_mac"], 0) + 1
    for n in nodes:
        n["client_count"] = counts.get(n["mac"], 0)
    cpu = 12.0 if rng is None else round(rng.uniform(8.0, 22.0), 1)
    mem = 41.0 if rng is None else round(rng.uniform(39.0, 45.0), 1)
    return {
        "fetched_at": _iso(),
        "nodes": nodes,
        "clients": clients,
        "wifi": _wifi(),
        "wan": _wan(),
        "performance": {"cpu_pct": cpu, "mem_pct": mem},
        "errors": {},
        "raw": {
            "note": DEMO_NOTE + " There are no raw Deco answers in demo mode.",
            "device_list": None,
            "client_list": None,
            "wlan": {"band6": {"host": {"ssid": "Demo Home", "password": "***", "channel": 37}}},
            "wan_ipv4": None,
            "performance": None,
            "ipv6": None,
        },
        # optional extra
        "demo": True,
    }


# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------

def demo_link() -> dict:
    """This computer: a Wi-Fi 7 MacBook in the Office, on 6 GHz at 160 MHz."""
    return {
        "os": "macos",
        "type": "wifi",
        "interface": "en0",
        "ssid": "Demo Home",
        "bssid": _node_bssids(OFFICE_MAC)["band6"],
        "band": "6GHz",
        "channel": 37,
        "width_mhz": 160,
        "phy": "802.11be",
        "wifi_gen": 7,
        "rssi_dbm": -63,
        "noise_dbm": -94,
        "snr_db": 31,
        "signal_pct": None,
        "tx_rate_mbps": 1441.0,
        "rx_rate_mbps": 1297.0,
        "error": None,
    }


def _p90(values: list) -> float:
    ordered = sorted(values)
    rank = max(1, int(round(0.9 * len(ordered) + 0.4999)))
    return ordered[min(len(ordered), rank) - 1]


def _target(name: str, host: str, port: int, center: float, spread: float,
            rng: random.Random, count: int = 15) -> dict:
    samples = []
    for _ in range(count):
        value = center + rng.gauss(0.0, spread)
        if rng.random() < 0.08:
            value += spread * rng.uniform(2.0, 4.0)  # the odd slow reply
        samples.append(round(max(0.6, value), 2))
    jitter = statistics.mean(abs(a - b) for a, b in zip(samples, samples[1:])) if len(samples) > 1 else 0.0
    return {
        "name": name,
        "host": host,
        "port": port,
        "samples_ms": samples,
        "median_ms": round(statistics.median(samples), 2),
        "p90_ms": round(_p90(samples), 2),
        "jitter_ms": round(jitter, 2),
        "loss_pct": 0.0,
    }


def demo_latency(gateway_ms: float = 4.1, internet_ms: float = 14.2,
                 rng: random.Random | None = None) -> dict:
    rng = rng or random.Random(68)
    return {
        "gateway": _target("Your Deco", "192.168.68.1", 80, gateway_ms, max(0.6, gateway_ms * 0.25), rng),
        "internet": [
            _target("Cloudflare", "1.1.1.1", 443, internet_ms, 1.6, rng),
            _target("Google", "8.8.8.8", 443, internet_ms + 2.6, 1.9, rng),
        ],
        "measured_at": _iso(),
        "error": None,
    }


def _grade(ms: float | None) -> str | None:
    if ms is None:
        return None
    if ms < 5:
        return "A+"
    if ms < 30:
        return "A"
    if ms < 60:
        return "B"
    if ms < 200:
        return "C"
    if ms < 400:
        return "D"
    return "F"


def demo_speed() -> dict:
    """412 down / 38 up on a 1000/50 plan, with 140 ms of bufferbloat (grade C)."""
    idle = 14.0
    loaded_down = 154.0
    loaded_up = 96.0
    bloat = max(loaded_down, loaded_up) - idle
    return {
        "down_mbps": 412.0,
        "up_mbps": 38.0,
        "idle_latency_ms": idle,
        "loaded_latency_down_ms": loaded_down,
        "loaded_latency_up_ms": loaded_up,
        "bufferbloat_ms": bloat,
        "bufferbloat_grade": _grade(bloat),
        "server": "speed.cloudflare.com (demo)",
        "duration_s": 17.4,
        "measured_at": _iso(),
        "error": None,
    }


_DNS_HOSTS = (
    ("www.google.com", 28.0),
    ("www.youtube.com", 31.0),
    ("www.apple.com", 34.0),
    ("www.netflix.com", 41.0),
    ("www.instagram.com", 38.0),
    ("www.tiktok.com", 36.0),
    ("discord.com", 30.0),
)


def demo_dns(rng: random.Random | None = None) -> dict:
    samples = []
    for host, ms in _DNS_HOSTS:
        if rng is not None:
            ms = max(2.0, ms * rng.uniform(0.75, 1.3))
        samples.append({"host": host, "ms": round(ms, 1), "ok": True})
    median = statistics.median(s["ms"] for s in samples)
    return {
        "median_ms": round(median, 1),
        "samples": samples,
        "resolvers": ["192.168.68.1"],
        "measured_at": _iso(),
        "error": None,
    }


# ---------------------------------------------------------------------------
# Rooms
# ---------------------------------------------------------------------------

# Known demo rooms: rssi, band, channel, width, down, up, internet ms, deco ms, node
_KNOWN_ROOMS = {
    "living room": (-52, "6GHz", 37, 160, 455.0, 39.0, 13.1, 3.6, MAIN_MAC),
    "office": (-63, "6GHz", 37, 160, 412.0, 38.0, 14.2, 4.1, OFFICE_MAC),
    "kitchen": (-68, "5GHz", 36, 160, 298.0, 36.0, 16.0, 6.4, MAIN_MAC),
    "upstairs bedroom": (-77, "5GHz", 36, 80, 96.0, 21.0, 24.5, 18.7, UPSTAIRS_MAC),
}

_STRONG_WORDS = ("living", "lounge", "office", "study", "den", "family")
_MEDIUM_WORDS = ("kitchen", "dining", "hall", "landing", "stairs")
_WEAK_WORDS = ("upstairs", "bedroom", "attic", "loft", "garage", "garden", "basement",
               "cellar", "yard", "patio", "bathroom", "shed", "balcony", "porch")

_NODE_NAMES = {MAIN_MAC: "Living Room", UPSTAIRS_MAC: "Upstairs Bedroom", OFFICE_MAC: "Office"}


def room_profile(room: str | None) -> dict:
    """Believable numbers for a room name (same name, same kind of numbers)."""
    key = " ".join((room or "office").lower().split())
    known = _KNOWN_ROOMS.get(key)
    if known:
        rssi, band, channel, width, down, up, lat, gw, node = known
        return {"rssi_dbm": rssi, "band": band, "channel": channel, "width_mhz": width,
                "down_mbps": down, "up_mbps": up, "latency_ms": lat, "gateway_ms": gw,
                "node_mac": node}

    quality = 0.4 + (zlib.crc32(key.encode("utf-8")) % 1000) / 2500.0  # 0.4 .. 0.8
    if any(w in key for w in _STRONG_WORDS):
        quality = 0.8
    if any(w in key for w in _MEDIUM_WORDS):
        quality = min(quality, 0.6)
    if any(w in key for w in _WEAK_WORDS):
        quality = min(quality, 0.3)

    rssi = int(round(-46 - (1.0 - quality) * 38))
    band = "6GHz" if rssi > -66 else "5GHz"
    width = 160 if rssi > -72 else 80
    if any(w in key for w in ("up", "bed", "attic", "loft")):
        node = UPSTAIRS_MAC
    elif any(w in key for w in ("office", "study", "desk")):
        node = OFFICE_MAC
    else:
        node = MAIN_MAC
    return {
        "rssi_dbm": rssi,
        "band": band,
        "channel": 37 if band == "6GHz" else 36,
        "width_mhz": width,
        "down_mbps": round(40.0 + 440.0 * quality ** 1.4, 1),
        "up_mbps": round(12.0 + 28.0 * quality, 1),
        "latency_ms": round(13.0 + (1.0 - quality) * 16.0, 1),
        "gateway_ms": round(3.0 + (1.0 - quality) * 22.0, 1),
        "node_mac": node,
    }


def demo_history() -> list:
    """Four saved room tests, oldest first. Upstairs Bedroom is the weakest."""
    now = _now()
    order = (("Living Room", 3 * 24 + 5), ("Office", 2 * 24 + 1), ("Kitchen", 26), ("Upstairs Bedroom", 3))
    out = []
    for room, hours_ago in order:
        p = room_profile(room)
        out.append({
            "room": room,
            "at": _iso(now - timedelta(hours=hours_ago)),
            "down_mbps": p["down_mbps"],
            "up_mbps": p["up_mbps"],
            "latency_ms": p["latency_ms"],
            "gateway_latency_ms": p["gateway_ms"],
            "rssi_dbm": p["rssi_dbm"],
            "band": p["band"],
            "width_mhz": p["width_mhz"],
            "phy": "802.11be",
            "bssid": _node_bssids(p["node_mac"])["band6" if p["band"] == "6GHz" else "band5"],
            "node_name": _NODE_NAMES[p["node_mac"]],
        })
    return out


def build_demo_snapshot() -> dict:
    """A complete, clearly-labelled demo Snapshot ("demo": True)."""
    return {
        "generated_at": _iso(),
        "demo": True,
        "demo_note": DEMO_NOTE,  # optional extra
        "settings": {
            "deco_host": "192.168.68.1",
            "plan_down_mbps": PLAN_DOWN,
            "plan_up_mbps": PLAN_UP,
            "room": "Office",
        },
        "deco": build_demo_deco(),
        "deco_error": None,
        "link": demo_link(),
        "latency": demo_latency(),
        "speed": demo_speed(),
        "dns": demo_dns(),
        "history": demo_history(),
    }


# ---------------------------------------------------------------------------
# Simulated runs (demo mode buttons). No network, just a short wait.
# ---------------------------------------------------------------------------

def _rng(rng: random.Random | None) -> random.Random:
    return rng if rng is not None else random.Random()


def _sleep_fn(sleep):
    return sleep if callable(sleep) else time.sleep


def _report(progress_cb, fraction: float, message: str) -> None:
    if progress_cb is None:
        return
    try:
        progress_cb(fraction, message)
    except Exception:
        pass


def simulate_deco(rng: random.Random | None = None, sleep=None) -> dict:
    _sleep_fn(sleep)(1.2)
    return build_demo_deco(_rng(rng))


def simulate_link(room: str | None = None, rng: random.Random | None = None, sleep=None) -> dict:
    rng = _rng(rng)
    _sleep_fn(sleep)(0.8)
    link = demo_link()
    p = room_profile(room)
    link["rssi_dbm"] = int(p["rssi_dbm"] + rng.randint(-2, 2))
    link["band"] = p["band"]
    link["channel"] = p["channel"]
    link["width_mhz"] = p["width_mhz"]
    link["bssid"] = _node_bssids(p["node_mac"])["band6" if p["band"] == "6GHz" else "band5"]
    link["snr_db"] = link["rssi_dbm"] - link["noise_dbm"]
    # Rough link rates for a 2x2 Wi-Fi 7 laptop at this signal and width.
    snr = link["snr_db"]
    full = 2882.0 if p["width_mhz"] >= 160 else 1441.0
    share = max(0.08, min(0.9, (snr - 5) / 40.0))
    link["tx_rate_mbps"] = float(int(full * share))
    link["rx_rate_mbps"] = float(int(full * share * 0.9))
    return link


def simulate_latency(room: str | None = None, rng: random.Random | None = None, sleep=None) -> dict:
    rng = _rng(rng)
    _sleep_fn(sleep)(1.5)
    p = room_profile(room)
    return demo_latency(p["gateway_ms"] * rng.uniform(0.85, 1.2),
                        p["latency_ms"] * rng.uniform(0.9, 1.15), rng)


def simulate_dns(rng: random.Random | None = None, sleep=None) -> dict:
    rng = _rng(rng)
    _sleep_fn(sleep)(0.7)
    return demo_dns(rng)


def simulate_speed(room: str | None = None, rng: random.Random | None = None,
                   progress_cb=None, sleep=None) -> dict:
    """A fake speed test with progress updates. Takes about 3 s at normal speed."""
    rng = _rng(rng)
    sleep = _sleep_fn(sleep)
    p = room_profile(room)
    down = round(p["down_mbps"] * rng.uniform(0.92, 1.06), 1)
    up = round(p["up_mbps"] * rng.uniform(0.92, 1.05), 1)
    idle = round(p["latency_ms"] * rng.uniform(0.95, 1.1), 1)
    loaded_down = round(idle + rng.uniform(120.0, 160.0), 1)
    loaded_up = round(idle + rng.uniform(60.0, 100.0), 1)

    _report(progress_cb, 0.02, "Checking the ping to the speed test server…")
    sleep(0.3)
    steps = 8
    for i in range(1, steps + 1):
        frac = 0.1 + 0.45 * i / steps
        _report(progress_cb, frac, "Testing download speed… %d Mbps" % int(down * min(1.0, 0.5 + i / steps)))
        sleep(0.15)
    for i in range(1, steps + 1):
        frac = 0.55 + 0.4 * i / steps
        _report(progress_cb, frac, "Testing upload speed… %d Mbps" % int(up * min(1.0, 0.5 + i / steps)))
        sleep(0.15)
    _report(progress_cb, 1.0, "Done")
    bloat = round(max(loaded_down, loaded_up) - idle, 1)
    result = demo_speed()
    result.update({
        "down_mbps": down,
        "up_mbps": up,
        "idle_latency_ms": idle,
        "loaded_latency_down_ms": loaded_down,
        "loaded_latency_up_ms": loaded_up,
        "bufferbloat_ms": bloat,
        "bufferbloat_grade": _grade(bloat),
        "duration_s": round(16.0 + rng.uniform(0.0, 2.0), 1),
        "measured_at": _iso(),
    })
    return copy.deepcopy(result)
