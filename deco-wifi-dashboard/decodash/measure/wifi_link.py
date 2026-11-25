"""Read this computer's own network link: Wi-Fi details or Ethernet.

It runs the tools that come with the operating system (``system_profiler``
on macOS, ``netsh`` on Windows, ``iw``/``nmcli`` on Linux) and reads their
text output. Nothing here changes any setting, and every command has a
timeout. ``get_link_info()`` and ``default_gateway()`` never raise.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import socket
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple

LINK_KEYS = (
    "os", "type", "interface", "ssid", "bssid", "band", "channel", "width_mhz",
    "phy", "wifi_gen", "rssi_dbm", "noise_dbm", "snr_db", "signal_pct",
    "tx_rate_mbps", "rx_rate_mbps", "error",
)

# Default-route interfaces that are VPN tunnels, not a real link.
_TUNNEL_PREFIXES = (
    "utun", "ipsec", "ppp", "tun", "tap", "wg", "tailscale", "zt", "gpd",
    "vpn", "nordlynx", "proton", "mullvad",
)

# Hides the black console window when Python runs a command on Windows.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_5GHZ_CHANNELS = (
    set(range(32, 69, 4)) | set(range(96, 145, 4)) | set(range(149, 178, 4))
)

_PHY_RANK = {"be": 7, "ax": 6, "ac": 5, "n": 4, "g": 3, "a": 2, "b": 1}

_MAX_COMMAND_S = 120.0  # no single OS command may run longer than this


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _blank_link(os_name: str) -> dict:
    info = {key: None for key in LINK_KEYS}
    info["os"] = os_name
    info["type"] = "unknown"
    return info


def _detect_os() -> str:
    plat = sys.platform
    if plat == "darwin":
        return "macos"
    if plat.startswith("win") or plat == "cygwin":
        return "windows"
    if plat.startswith("linux"):
        return "linux"
    return "other"


def _decode(data: bytes | None) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    for encoding in ("oem", "mbcs"):  # Windows console code pages
        try:
            return data.decode(encoding, errors="replace")
        except LookupError:
            continue
    return data.decode("latin-1", errors="replace")


def _run(cmd: list, timeout: float) -> str | None:
    """Run a command and return its stdout, or None if it could not run."""
    try:
        limit = float(timeout)
    except (TypeError, ValueError):
        limit = 5.0
    if not limit > 0:  # also catches NaN
        limit = 5.0
    limit = max(0.2, min(limit, _MAX_COMMAND_S))  # subprocess can't wait "forever"
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=limit,
            creationflags=_NO_WINDOW,
            check=False,
        )
    except Exception:  # not installed, timed out, no permission, ...
        return None
    return _decode(proc.stdout)


def _left(deadline: float, cap: float | None = None) -> float:
    remaining = max(0.5, deadline - time.monotonic())
    if cap is not None:
        remaining = min(cap, remaining)
    return remaining


def _read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except Exception:
        return None


def _num(value: Any) -> float | None:
    """First number in a value ("1201", 1201, "2401.9 MBit/s"), else None."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None  # JSON allows NaN/Infinity
    match = re.search(r"-?\d+(?:\.\d+)?", str(value))
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def _int(value: Any) -> int | None:
    number = _num(value)
    return None if number is None else int(round(number))


def _norm_mac(value: Any) -> str | None:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    parts = re.split(r"[:\-]", text)
    if len(parts) != 6:
        if re.fullmatch(r"[0-9A-Fa-f]{12}", text):
            parts = [text[i:i + 2] for i in range(0, 12, 2)]
        else:
            return None
    if not all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in parts):
        return None
    mac = ":".join(p.zfill(2).upper() for p in parts)
    if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return None
    return mac


def _clean_ssid(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if re.fullmatch(r"<\s*(redacted|hidden|unknown|private|ssid)[^>]*>", text, re.I):
        return None
    if text.lower() in ("redacted", "<redacted>"):
        return None
    return text


def _is_ip(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return True


def _is_ipv4(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _is_tunnel(name: str | None) -> bool:
    return bool(name) and str(name).lower().startswith(_TUNNEL_PREFIXES)


def _band_from_channel(channel: int | None) -> str | None:
    """Best guess when only a channel number is known."""
    if channel is None:
        return None
    if 1 <= channel <= 14:
        return "2.4GHz"
    if channel in _5GHZ_CHANNELS:
        return "5GHz"
    if channel == 2 or (channel % 4 == 1 and 1 <= channel <= 233):
        return "6GHz"
    return None


def _band_from_text(text: Any) -> str | None:
    if text is None:
        return None
    match = re.search(r"(\d+(?:\.\d+)?)\s*GHz", str(text), re.I)
    if not match:
        return None
    ghz = float(match.group(1))
    if 2.0 <= ghz < 3.0:
        return "2.4GHz"
    if 4.5 <= ghz < 5.9:
        return "5GHz"
    if 5.9 <= ghz < 7.5:
        return "6GHz"
    return None


def _freq_to_band_channel(freq: Any) -> Tuple[str | None, int | None]:
    number = _num(freq)
    if number is None:
        return None, None
    mhz = int(round(number))
    if mhz == 2484:
        return "2.4GHz", 14
    if 2400 <= mhz < 2500:
        return "2.4GHz", (mhz - 2407) // 5
    if mhz == 5935:
        return "6GHz", 2
    if 5940 <= mhz <= 7125:
        return "6GHz", (mhz - 5950) // 5
    if 4900 <= mhz < 5000:  # Japan's 4.9 GHz channels (182-196) count from 4000 MHz
        return "5GHz", (mhz - 4000) // 5
    if 5000 <= mhz < 5935:
        return "5GHz", (mhz - 5000) // 5
    return None, None


def _norm_phy(value: Any) -> Tuple[str | None, int | None]:
    """Return ("802.11be", 7) style (phy, wifi_gen) from free text."""
    if value is None:
        return None, None
    text = str(value).strip()
    if not text:
        return None, None
    low = text.lower().replace("802.", " ")
    best = None
    for group in re.findall(r"11\s*([a-z/ ,]+)", low):
        for token in re.split(r"[/ ,]+", group):
            if token in _PHY_RANK and (best is None or _PHY_RANK[token] > _PHY_RANK[best]):
                best = token
    if best is None:
        return text, None
    gen = _PHY_RANK[best]
    return "802.11" + best, (gen if gen >= 4 else None)


def _phy_gen(phy: Any) -> int | None:
    return _norm_phy(phy)[1]


def _estimate_rssi(pct: int | None) -> int | None:
    if pct is None:
        return None
    return int(round(pct / 2.0 - 100))


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------

def _parse_mac_channel(value: Any) -> Tuple[int | None, str | None, int | None]:
    if value is None or isinstance(value, bool):
        return None, None, None
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            return None, None, None
        channel = int(value)
        return channel, _band_from_channel(channel), None
    text = str(value)
    match = re.match(r"\s*(\d+)", text)
    channel = int(match.group(1)) if match else None
    band = _band_from_text(text) or _band_from_channel(channel)
    width = None
    width_match = re.search(r"(\d+)\s*MHz", text, re.I)
    if width_match:
        width = int(width_match.group(1))
    elif re.search(r",\s*[+-]1\b", text):  # old "149,+1" style means 40 MHz
        width = 40
    return channel, band, width


def parse_macos_system_profiler(json_text: str) -> dict:
    """Parse ``system_profiler SPAirPortDataType -json`` into LinkInfo fields."""
    out: Dict[str, Any] = {"type": "unknown"}
    try:
        data = json.loads(json_text or "")
    except (ValueError, TypeError):
        out["error"] = "macOS didn't give a readable Wi-Fi report."
        return out
    interfaces: List[dict] = []
    entries = data.get("SPAirPortDataType") if isinstance(data, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        found = entry.get("spairport_airport_interfaces")
        for iface in found if isinstance(found, list) else []:
            if isinstance(iface, dict):
                interfaces.append(iface)
    if not interfaces:
        out["error"] = "No Wi-Fi adapter was found on this Mac."
        return out

    chosen = None
    for iface in interfaces:
        current = iface.get("spairport_current_network_information")
        if isinstance(current, dict) and current:
            chosen = (iface, current)
            break

    if chosen is None:
        for iface in interfaces:
            name = iface.get("_name")
            if isinstance(name, str) and not name.startswith(("awdl", "llw")):
                out["interface"] = name
                status = str(iface.get("spairport_status_information") or "").lower()
                if status.endswith("off"):
                    out["error"] = "Wi-Fi is turned off on this Mac."
                break
        out.setdefault("error", "Wi-Fi isn't connected to a network right now.")
        return out

    iface, current = chosen
    out["type"] = "wifi"
    out["interface"] = iface.get("_name") if isinstance(iface.get("_name"), str) else None
    out["ssid"] = _clean_ssid(current.get("_name"))

    for key, value in current.items():
        if "bssid" in str(key).lower():
            out["bssid"] = _norm_mac(value)
            break

    channel, band, width = _parse_mac_channel(current.get("spairport_network_channel"))
    if band is None:
        for key, value in current.items():
            if "band" in str(key).lower():
                band = _band_from_text(value)
                if band:
                    break
    out["channel"] = channel
    out["band"] = band
    out["width_mhz"] = width

    phy, gen = _norm_phy(current.get("spairport_network_phymode"))
    out["phy"] = phy
    out["wifi_gen"] = gen

    rate = _num(current.get("spairport_network_rate"))
    out["tx_rate_mbps"] = rate if rate and rate > 0 else None

    mcs = _int(current.get("spairport_network_mcs"))
    if mcs is not None:
        out["mcs"] = mcs

    signal_noise = current.get("spairport_signal_noise")
    rssi = noise = None
    if signal_noise is not None:
        numbers = [int(n) for n in re.findall(r"-?\d+", str(signal_noise))]
        if numbers:
            rssi = numbers[0]
        if len(numbers) > 1:
            noise = numbers[1]
    if rssi is None:
        for key, value in current.items():
            if "rssi" in str(key).lower():
                rssi = _int(value)
                break
    if rssi is not None and not -120 <= rssi < 0:
        rssi = None
    if noise is not None and not -130 <= noise < 0:
        noise = None
    out["rssi_dbm"] = rssi
    out["noise_dbm"] = noise
    if rssi is not None and noise is not None:
        out["snr_db"] = rssi - noise
    return out


def parse_macos_hardware_ports(text: str) -> str | None:
    """Wi-Fi device name (e.g. "en0") from ``networksetup -listallhardwareports``."""
    port = None
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("hardware port:"):
            port = stripped.split(":", 1)[1].strip().lower()
        elif stripped.lower().startswith("device:") and port is not None:
            if port in ("wi-fi", "wifi", "airport", "wlan"):
                device = stripped.split(":", 1)[1].strip()
                return device or None
            port = None
    return None


def parse_macos_route_get(text: str) -> Tuple[str | None, str | None]:
    """(gateway, interface) from ``route -n get default``."""
    gateway = interface = None
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "gateway" and _is_ip(value):
            gateway = value
        elif key == "interface" and value:
            interface = value
    return gateway, interface


def parse_macos_netstat(text: str) -> Tuple[str | None, str | None]:
    """(gateway, interface) from ``netstat -rn -f inet``."""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "default" and _is_ipv4(parts[1]):
            return parts[1], parts[3]
    return None, None


def parse_ifconfig_media_speed(text: str) -> int | None:
    """Ethernet link speed in Mbps from macOS ``ifconfig`` "media:" line."""
    for line in (text or "").splitlines():
        if "media:" not in line:
            continue
        match = re.search(r"\(?\s*(\d+(?:\.\d+)?)\s*(G)?base", line, re.I)
        if match:
            value = float(match.group(1))
            if match.group(2):
                value *= 1000
            return int(value)
    return None


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

_NETSH_LINE = re.compile(r"^\s*(.+?)\s+:\s?(.*)$")
_NETSH_UNREADABLE = ("Couldn't read Wi-Fi details from Windows. This tool reads the English "
                     "version of Windows' Wi-Fi report best.")


def _netsh_blocks(text: str) -> List[Dict[str, str]]:
    blocks: List[Dict[str, str]] = []
    current: Dict[str, str] | None = None
    for line in (text or "").splitlines():
        match = _NETSH_LINE.match(line)
        if not match:
            continue
        key = re.sub(r"\s+", " ", match.group(1).strip().lower())
        value = match.group(2).strip()
        if key == "name":
            current = {}
            blocks.append(current)
        if current is None:
            continue
        current.setdefault(key, value)
    return blocks


def parse_windows_netsh(text: str) -> dict:
    """Parse ``netsh wlan show interfaces`` (English Windows)."""
    out: Dict[str, Any] = {"type": "unknown"}
    low = (text or "").lower()
    blocks = _netsh_blocks(text or "")
    if not blocks:
        if "location permission" in low or "location services" in low:
            # Windows 11 24H2+ hides Wi-Fi details until Location is allowed.
            out["needs_location_permission"] = True
            out["error"] = ("Windows hides Wi-Fi details until Location is on. Turn it on in "
                            "Settings → Privacy & security → Location (also allow desktop "
                            "apps), then run the test again.")
        elif "no wireless interface" in low:
            out["error"] = "This computer has no Wi-Fi adapter, or it's turned off."
        elif "wlansvc" in low or "autoconfig" in low:
            out["error"] = "The Windows Wi-Fi service (WLAN AutoConfig) isn't running."
        else:
            out["error"] = _NETSH_UNREADABLE
        return out

    chosen = None
    for block in blocks:
        if block.get("state", "").strip().lower() == "connected":
            chosen = block
            break
    if chosen is None:
        out["interface"] = blocks[0].get("name") or None
        if any("state" in block for block in blocks):
            out["error"] = "Wi-Fi isn't connected to a network right now."
        else:  # e.g. German "Status : Verbunden": we can't tell what it says
            out["error"] = _NETSH_UNREADABLE
        return out

    out["type"] = "wifi"
    out["interface"] = chosen.get("name") or None
    out["ssid"] = _clean_ssid(chosen.get("ssid"))
    out["bssid"] = _norm_mac(chosen.get("ap bssid") or chosen.get("bssid"))

    phy, gen = _norm_phy(chosen.get("radio type"))
    out["phy"] = phy
    out["wifi_gen"] = gen

    channel = _int(chosen.get("channel"))
    out["channel"] = channel
    out["band"] = _band_from_text(chosen.get("band")) or _band_from_channel(channel)

    rx = tx = None
    for key, value in chosen.items():
        if key.startswith("receive rate"):
            rx = _num(value)
        elif key.startswith("transmit rate"):
            tx = _num(value)
    out["rx_rate_mbps"] = rx
    out["tx_rate_mbps"] = tx

    pct = _int(chosen.get("signal"))
    if pct is not None:
        pct = max(0, min(100, pct))
    out["signal_pct"] = pct

    rssi = _int(chosen.get("rssi"))
    if rssi is not None and not -120 <= rssi < 0:
        rssi = None
    if rssi is None and pct is not None:
        rssi = _estimate_rssi(pct)
        out["rssi_estimated"] = True
    out["rssi_dbm"] = rssi
    return out


def parse_windows_route_print(text: str) -> str | None:
    """Default gateway with the lowest metric from ``route print``."""
    best: Tuple[int, str] | None = None
    in_active = False
    for line in (text or "").splitlines():
        low = line.strip().lower()
        if low.startswith("active routes"):
            in_active = True
            continue
        if low.startswith("persistent routes") or low.startswith("ipv6 route table"):
            in_active = False
            continue
        if not in_active:
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gateway = parts[2]
            if not _is_ipv4(gateway):
                continue
            try:
                metric = int(parts[4])
            except ValueError:
                metric = 9999
            if best is None or metric < best[0]:
                best = (metric, gateway)
    return best[1] if best else None


def parse_windows_ipconfig_gateway(text: str) -> str | None:
    """First IPv4 "Default Gateway" from ``ipconfig``."""
    collecting = False
    for line in (text or "").splitlines():
        if re.match(r"^\s*Default Gateway[ .]*:", line, re.I):
            collecting = True
            value = line.split(":", 1)[1].strip()
            if _is_ipv4(value):
                return value
            continue
        if collecting:
            value = line.strip()
            if _is_ipv4(value):
                return value
            if value and _is_ip(value):
                continue
            collecting = False
    return None


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

def _width_from_tokens(text: str) -> int | None:
    widths: List[int] = []
    for match in re.finditer(r"\b(\d+)(P80)?MHz\b", text, re.I):
        widths.append(160 if match.group(2) else int(match.group(1)))
    for match in re.finditer(r"\b(?:EHT|HE|VHT|HT)(\d{2,3})\b", text):
        widths.append(int(match.group(1)))
    widths = [w for w in widths if w in (20, 40, 80, 160, 320)]
    return max(widths) if widths else None


def _phy_from_tokens(text: str) -> str | None:
    if re.search(r"\bEHT(?:-|\d)", text):
        return "802.11be"
    if re.search(r"\bHE(?:-|\d)", text):
        return "802.11ax"
    if re.search(r"\bVHT(?:-|\d)", text):
        return "802.11ac"
    if re.search(r"\bMCS\b", text) or re.search(r"\bHT\d", text):
        return "802.11n"
    return None


def parse_linux_iw(link_text: str, info_text: str = "") -> dict:
    """Parse ``iw dev <dev> link`` (and optionally ``iw dev <dev> info``)."""
    out: Dict[str, Any] = {"type": "unknown"}
    link_text = link_text or ""
    info_text = info_text or ""
    info_iface = re.search(r"^\s*Interface\s+(\S+)", info_text, re.M)
    connected = re.search(
        r"Connected to\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?:\s*\(on\s+([^)\s]+)\))?",
        link_text,
    )
    if not connected:
        if info_iface:
            out["interface"] = info_iface.group(1)
        if "not connected" in link_text.lower():
            out["error"] = "Wi-Fi isn't connected to a network right now."
        else:
            out["error"] = "Couldn't read Wi-Fi details from Linux."
        return out

    out["type"] = "wifi"
    out["bssid"] = _norm_mac(connected.group(1))
    out["interface"] = connected.group(2) or (info_iface.group(1) if info_iface else None)

    ssid = re.search(r"^\s*SSID:\s?(.*)$", link_text, re.M)
    out["ssid"] = _clean_ssid(ssid.group(1)) if ssid else None

    band = channel = None
    freq = re.search(r"^\s*freq:\s*([\d.]+)", link_text, re.M)
    if freq:
        band, channel = _freq_to_band_channel(freq.group(1))
    info_channel = re.search(r"channel\s+(\d+)\s*\(\s*([\d.]+)\s*MHz\)", info_text)
    if info_channel:
        if channel is None:
            channel = int(info_channel.group(1))
        if band is None:
            band = _freq_to_band_channel(info_channel.group(2))[0]
    out["band"] = band
    out["channel"] = channel

    signal = re.search(r"^\s*signal:\s*(-?\d+)", link_text, re.M)
    out["rssi_dbm"] = int(signal.group(1)) if signal else None

    rates_text = ""
    for direction in ("rx", "tx"):
        rate = re.search(
            r"^\s*%s bitrate:\s*([\d.]+)\s*MBit/s(.*)$" % direction, link_text, re.M | re.I
        )
        if rate:
            out["%s_rate_mbps" % direction] = float(rate.group(1))
            rates_text += " " + rate.group(2)

    phy = _phy_from_tokens(rates_text)
    out["phy"] = phy
    out["wifi_gen"] = _phy_gen(phy)

    width = None
    info_width = re.search(r"width:\s*(\d+)\s*MHz", info_text, re.I)
    if info_width:
        width = int(info_width.group(1))
    if width is None:
        width = _width_from_tokens(rates_text)
    if width is None and phy is not None:
        width = 20  # iw prints no width token for 20 MHz rates
    out["width_mhz"] = width
    return out


def _split_nmcli(line: str) -> List[str]:
    fields: List[str] = []
    current = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def parse_nmcli_wifi(text: str) -> dict:
    """Parse ``nmcli -t -f ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL device wifi list``."""
    out: Dict[str, Any] = {"type": "unknown"}
    for line in (text or "").splitlines():
        fields = _split_nmcli(line.strip())
        if len(fields) < 7:
            continue
        active, ssid, bssid, chan, freq, rate, signal = fields[:7]
        if active.strip().lower() not in ("yes", "*"):
            continue
        out["type"] = "wifi"
        out["ssid"] = _clean_ssid(ssid)
        out["bssid"] = _norm_mac(bssid)
        band, channel = _freq_to_band_channel(freq)
        out["channel"] = _int(chan) if _int(chan) is not None else channel
        out["band"] = band or _band_from_channel(out["channel"])
        out["tx_rate_mbps"] = _num(rate)
        pct = _int(signal)
        out["signal_pct"] = pct
        if pct is not None:
            out["rssi_dbm"] = _estimate_rssi(pct)
            out["rssi_estimated"] = True
        return out
    out["error"] = "Wi-Fi isn't connected to a network right now."
    return out


def parse_linux_ip_route(text: str) -> Tuple[str | None, str | None]:
    """(gateway, dev) with the lowest metric from ``ip route show default``."""
    best: Tuple[int, str | None, str | None] | None = None
    for line in (text or "").splitlines():
        tokens = line.split()
        if not tokens or tokens[0] != "default":
            continue
        gateway = dev = None
        metric = 0
        for i, token in enumerate(tokens[:-1]):
            nxt = tokens[i + 1]
            if token == "via" and _is_ip(nxt):
                gateway = nxt
            elif token == "dev":
                dev = nxt
            elif token == "metric":
                try:
                    metric = int(nxt)
                except ValueError:
                    pass
        if best is None or metric < best[0]:
            best = (metric, gateway, dev)
    if best is None:
        return None, None
    return best[1], best[2]


def parse_proc_net_route(text: str) -> Tuple[str | None, str | None]:
    """(gateway, dev) from /proc/net/route (gateway is little-endian hex)."""
    best: Tuple[int, str | None, str] | None = None
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8 or parts[1] != "00000000":
            continue
        try:
            flags = int(parts[3], 16)
            if not flags & 0x1:  # RTF_UP
                continue
            gw_int = int(parts[2], 16)
            metric = int(parts[6])
        except ValueError:
            continue
        gateway = socket.inet_ntoa(struct.pack("<I", gw_int)) if gw_int else None
        if best is None or metric < best[0]:
            best = (metric, gateway, parts[0])
    if best is None:
        return None, None
    return best[1], best[2]


def _sys_wireless(dev: str) -> bool:
    base = os.path.join("/sys/class/net", dev)
    return os.path.isdir(os.path.join(base, "wireless")) or os.path.exists(
        os.path.join(base, "phy80211")
    )


def _list_sys_wireless() -> List[str]:
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []
    return [name for name in names if _sys_wireless(name)]


def _linux_default_route(timeout: float) -> Tuple[str | None, str | None]:
    text = _run(["ip", "route", "show", "default"], timeout)
    gateway, dev = parse_linux_ip_route(text or "")
    if gateway or dev:
        return gateway, dev
    return parse_proc_net_route(_read_text("/proc/net/route") or "")


# "iw" is often in /usr/sbin, which isn't on a normal user's PATH everywhere.
_IW_CANDIDATES = ("iw", "/usr/sbin/iw", "/sbin/iw")


def _linux_wifi(dev: str, deadline: float) -> dict | None:
    """Wi-Fi details for one Linux interface, or None if it isn't Wi-Fi."""
    link = None
    iw = "iw"
    for iw in _IW_CANDIDATES:
        link = _run([iw, "dev", dev, "link"], _left(deadline, 3.0))
        if link is not None:
            break
    if link and ("Connected to" in link or "Not connected" in link):
        info = _run([iw, "dev", dev, "info"], _left(deadline, 3.0)) or ""
        result = parse_linux_iw(link, info)
        if not result.get("interface"):
            result["interface"] = dev
        return result
    if not _sys_wireless(dev):
        return None
    base = ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL",
            "device", "wifi", "list", "ifname", dev]
    text = _run(base + ["--rescan", "no"], _left(deadline, 4.0))
    if not text or not text.strip():
        text = _run(base, _left(deadline, 4.0))
    result = parse_nmcli_wifi(text or "")
    result["interface"] = dev
    if result.get("type") != "wifi" and not text:
        result["error"] = "Couldn't read Wi-Fi details (install the 'iw' tool for more)."
    return result


def _linux_link(deadline: float) -> dict:
    gateway, dev = _linux_default_route(_left(deadline, 3.0))
    if dev and not _is_tunnel(dev):
        wifi = _linux_wifi(dev, deadline)
        if wifi is not None:
            return wifi
        result: Dict[str, Any] = {"type": "ethernet", "interface": dev}
        speed = _int(_read_text("/sys/class/net/%s/speed" % dev))
        if speed is not None and speed > 0:
            result["link_speed_mbps"] = speed
        return result
    # No default route, or it goes through a VPN tunnel: look for Wi-Fi.
    for name in _list_sys_wireless():
        wifi = _linux_wifi(name, deadline)
        if wifi is not None and wifi.get("type") == "wifi":
            if dev:
                wifi["vpn"] = True
            return wifi
    if dev:
        return {"type": "unknown", "interface": dev, "vpn": True,
                "error": "Your traffic goes through a VPN, so the real link type is hidden."}
    return {"type": "unknown",
            "error": "This computer doesn't seem to be connected to a network."}


# ---------------------------------------------------------------------------
# per-OS link readers
# ---------------------------------------------------------------------------

def _decide(wifi: dict, wifi_dev: str | None, def_iface: str | None,
            gateway: str | None) -> dict:
    """Pick Wi-Fi or Ethernet from the Wi-Fi report and the default route."""
    tunnel = _is_tunnel(def_iface)
    wifi_up = wifi.get("type") == "wifi"
    wifi_names = {n for n in (wifi_dev, wifi.get("interface")) if n}
    if wifi_up and (not def_iface or tunnel or def_iface in wifi_names):
        result = dict(wifi)
        if tunnel:
            result["vpn"] = True
        return result
    if def_iface and not tunnel and wifi_dev and def_iface == wifi_dev:
        # The traffic goes out through the Wi-Fi adapter, so this is Wi-Fi even
        # though the Wi-Fi report failed or came back empty. Never call it a cable.
        return {"type": "wifi", "interface": def_iface,
                "error": "This Mac is on Wi-Fi, but macOS didn't share the details "
                         "(signal, band, speed) this time. Try the test again."}
    if def_iface and not tunnel:
        return {"type": "ethernet", "interface": def_iface}
    if tunnel:
        return {"type": "unknown", "interface": def_iface, "vpn": True,
                "error": "Your traffic goes through a VPN, so the real link type is hidden."}
    if gateway:
        return {"type": "ethernet", "interface": None}
    return {"type": "unknown", "interface": wifi.get("interface"),
            "error": wifi.get("error")
            or "This computer doesn't seem to be connected to a network."}


def _macos_link(deadline: float) -> dict:
    route = _run(["route", "-n", "get", "default"], _left(deadline, 3.0))
    gateway, def_iface = parse_macos_route_get(route or "")
    ports = _run(["networksetup", "-listallhardwareports"], _left(deadline, 3.0))
    wifi_dev = parse_macos_hardware_ports(ports or "")
    report = _run(["system_profiler", "SPAirPortDataType", "-json"], _left(deadline))
    if report and report.strip():
        wifi = parse_macos_system_profiler(report)
    else:
        wifi = {"type": "unknown", "interface": wifi_dev,
                "error": "macOS didn't share Wi-Fi details in time."}
    result = _decide(wifi, wifi_dev, def_iface, gateway)
    if result.get("type") == "ethernet" and result.get("interface"):
        media = _run(["ifconfig", result["interface"]], _left(deadline, 2.0))
        speed = parse_ifconfig_media_speed(media or "")
        if speed:
            result["link_speed_mbps"] = speed
    return result


def _windows_gateway(timeout: float) -> str | None:
    text = _run(["route", "print", "0.0.0.0"], timeout)
    gateway = parse_windows_route_print(text or "")
    if gateway:
        return gateway
    return parse_windows_ipconfig_gateway(_run(["ipconfig"], timeout) or "")


def _netsh_says_no_wifi(text: str | None) -> bool:
    """True only when netsh clearly reports that Wi-Fi isn't in use."""
    if not text:
        return False  # netsh didn't run or timed out: we know nothing
    low = text.lower()
    if "no wireless interface" in low or "wlansvc" in low or "autoconfig" in low:
        return True  # no Wi-Fi adapter, or the Wi-Fi service is off
    blocks = _netsh_blocks(text)
    return bool(blocks) and all("state" in block for block in blocks)


def _windows_link(deadline: float) -> dict:
    text = _run(["netsh", "wlan", "show", "interfaces"], _left(deadline, 5.0))
    wifi = parse_windows_netsh(text or "")
    if wifi.get("type") == "wifi" or wifi.get("needs_location_permission"):
        return wifi  # without Location we can't tell Wi-Fi from cable, so don't guess
    # Only call it a cable when Windows clearly said Wi-Fi is off or not
    # connected. A failed, timed-out or non-English report could still be Wi-Fi.
    if _netsh_says_no_wifi(text) and _windows_gateway(_left(deadline, 3.0)):
        return {"type": "ethernet", "interface": None}
    return {"type": "unknown", "interface": wifi.get("interface"),
            "error": wifi.get("error")
            or "This computer doesn't seem to be connected to a network."}


_WIFI_ONLY_KEYS = ("ssid", "bssid", "band", "channel", "width_mhz", "phy", "wifi_gen",
                   "rssi_dbm", "noise_dbm", "snr_db", "signal_pct")


def get_link_info(timeout: float = 8.0) -> dict:
    """LinkInfo for this computer. Never raises."""
    os_name = "other"
    try:
        os_name = _detect_os()
    except Exception:
        pass
    info = _blank_link(os_name)
    try:
        try:
            budget = float(timeout)
        except (TypeError, ValueError):
            budget = 8.0
        if not budget > 0:
            budget = 8.0
        budget = min(budget, _MAX_COMMAND_S)  # an endless budget would break the timeouts
        deadline = time.monotonic() + budget
        if os_name == "macos":
            found = _macos_link(deadline)
        elif os_name == "windows":
            found = _windows_link(deadline)
        elif os_name == "linux":
            found = _linux_link(deadline)
        else:
            found = {"error": "Reading the network link isn't supported on this system yet."}
        for key, value in found.items():
            if key != "os":
                info[key] = value
        if info.get("type") not in ("wifi", "ethernet", "unknown"):
            info["type"] = "unknown"
        if info["type"] == "wifi":
            if info.get("phy") and info.get("wifi_gen") is None:
                info["wifi_gen"] = _phy_gen(info["phy"])
            if (info.get("snr_db") is None and info.get("rssi_dbm") is not None
                    and info.get("noise_dbm") is not None):
                info["snr_db"] = info["rssi_dbm"] - info["noise_dbm"]
        else:
            for key in _WIFI_ONLY_KEYS:
                info[key] = None
            info.pop("rssi_estimated", None)
            info.pop("mcs", None)
            if info["type"] == "ethernet":
                info["error"] = None
                speed = info.get("link_speed_mbps")
                if speed:
                    # For a cable, the link speed plays the role of the Wi-Fi rate.
                    info["tx_rate_mbps"] = float(speed)
                    info["rx_rate_mbps"] = float(speed)
                else:
                    info["tx_rate_mbps"] = None
                    info["rx_rate_mbps"] = None
    except Exception as exc:  # never raise
        info["error"] = "Couldn't read this computer's connection: %s" % (exc,)
    return info


def default_gateway() -> str | None:
    """The default gateway (router) IP address, or None. Never raises."""
    try:
        os_name = _detect_os()
        if os_name == "macos":
            gateway, _ = parse_macos_route_get(_run(["route", "-n", "get", "default"], 3.0) or "")
            if not gateway:
                gateway, _ = parse_macos_netstat(_run(["netstat", "-rn", "-f", "inet"], 3.0) or "")
            return gateway
        if os_name == "linux":
            return _linux_default_route(3.0)[0]
        if os_name == "windows":
            return _windows_gateway(4.0)
    except Exception:
        return None
    return None
