"""Facts about TP-Link Deco models and where settings live in the Deco app.

Every fact here was checked against a public source in November 2026. The
source URL sits in a comment next to the fact. Facts we could not confirm are
left out, or the user text that uses them is hedged ("if your app shows it").

The analyzer (``decodash/analyze.py``) and the web UI read this module. It is
plain data plus one lookup helper, :func:`model_info`.
"""

from __future__ import annotations

import copy
import re

# ---------------------------------------------------------------------------
# Deco models
# ---------------------------------------------------------------------------
#
# Keys are upper-case model codes as the Deco reports them in "device_model"
# (for example "BE65"). ``model_info`` also accepts "Deco BE65", "be65(US)",
# "BE65 v2" and similar spellings.
#
# Field meanings:
#   name              marketing name
#   marketing_class   the "BE11000"-style speed class on the box
#   wifi_gen          7 = Wi-Fi 7 (802.11be), 6 = Wi-Fi 6/6E (802.11ax)
#   bands             radio bands for devices, using the SPEC band keys
#   max_rates_mbps    top PHY rate per band from TP-Link's spec sheet
#   ports             human description of the Ethernet ports on ONE unit
#   port_count        number of Ethernet ports on one unit
#   max_port_gbps     speed of the fastest Ethernet port on one unit
#   multi_gig         True when at least one port is faster than 1 Gbps
#   supports_320mhz   320 MHz channels (TP-Link: 6 GHz band only)
#   supports_mlo      Multi-Link Operation (a Wi-Fi 7 feature)
#   max_5ghz_width_mhz  widest 5 GHz channel TP-Link lists (only where checked)
#   notes             short extra facts
#   sources           where the facts come from

MODELS = {
    # Deco BE65 is the model sold as "BE11000 Whole Home Mesh WiFi 7 System".
    # Source (v2 page): https://www.tp-link.com/en/home-networking/deco/deco-be65/v2
    #   - 6 GHz 5765 Mbps, 5 GHz 4324 Mbps, 2.4 GHz 688 Mbps (v2 spec table)
    #   - "4x 2.5 Gbps" ports per unit, WAN/LAN auto-sensing
    #   - 320 MHz: "only available on the 6 GHz band", may be limited by region
    #   - Multi-Link Operation (MLO) listed; needs client support
    # Source (v1 US datasheet, via search): 6 GHz 5760, 5 GHz 4320,
    #   2.4 GHz 574 Mbps (802.11ax), 4 x 2.5 Gigabit ports per unit:
    #   https://static.tp-link.com/upload/product-overview/2023/202305/20230526/Deco BE65 (US)1.0_Datasheet.pdf
    "BE65": {
        "name": "Deco BE65",
        "marketing_class": "BE11000",
        "wifi_gen": 7,
        "bands": ["band2_4", "band5", "band6"],
        "max_rates_mbps": {"band6": 5765, "band5": 4324, "band2_4": 688},
        "ports": "4 x 2.5 Gbps Ethernet ports per unit",
        "port_count": 4,
        "max_port_gbps": 2.5,
        "multi_gig": True,
        "supports_320mhz": True,
        "supports_mlo": True,
        "max_5ghz_width_mhz": None,
        "notes": [
            "320 MHz works on the 6 GHz band only and may be limited by local rules.",
            "Hardware v1 lists 574 Mbps on 2.4 GHz; v2 lists 688 Mbps.",
        ],
        "sources": [
            "https://www.tp-link.com/en/home-networking/deco/deco-be65/v2",
            "https://static.tp-link.com/upload/product-overview/2023/202305/20230526/Deco BE65 (US)1.0_Datasheet.pdf",
        ],
    },
    # Deco BE65 Pro is ALSO sold as "BE11000", but has different ports.
    # Source: https://www.tp-link.com/ca/home-networking/deco/deco-be65-pro/
    #   - "5764 Mbps (6 GHz) + 4324 Mbps (5 GHz) + 688 Mbps (2.4 GHz)"
    #   - "2x 5 Gbps WAN/LAN Ports + 1x 2.5 Gbps WAN/LAN Port"
    #   - 320 MHz (6 GHz only) and MLO listed
    "BE65 PRO": {
        "name": "Deco BE65 Pro",
        "marketing_class": "BE11000",
        "wifi_gen": 7,
        "bands": ["band2_4", "band5", "band6"],
        "max_rates_mbps": {"band6": 5764, "band5": 4324, "band2_4": 688},
        "ports": "2 x 5 Gbps + 1 x 2.5 Gbps Ethernet ports per unit",
        "port_count": 3,
        "max_port_gbps": 5.0,
        "multi_gig": True,
        "supports_320mhz": True,
        "supports_mlo": True,
        "max_5ghz_width_mhz": None,
        "notes": ["320 MHz works on the 6 GHz band only."],
        "sources": ["https://www.tp-link.com/ca/home-networking/deco/deco-be65-pro/"],
    },
    # Deco BE63 ("Deco 7 Pro BE10000").
    # Source: https://www.tp-link.com/us/deco-mesh-wifi/product-family/deco-be63/
    #   - 6 GHz 5188 Mbps, 5 GHz 4324 Mbps, 2.4 GHz 574 Mbps (802.11ax)
    #   - "4x 2.5 Gbps" per Deco unit, WAN/LAN auto-sensing
    #   - 320 MHz (6 GHz only) and MLO listed
    "BE63": {
        "name": "Deco BE63",
        "marketing_class": "BE10000",
        "wifi_gen": 7,
        "bands": ["band2_4", "band5", "band6"],
        "max_rates_mbps": {"band6": 5188, "band5": 4324, "band2_4": 574},
        "ports": "4 x 2.5 Gbps Ethernet ports per unit",
        "port_count": 4,
        "max_port_gbps": 2.5,
        "multi_gig": True,
        "supports_320mhz": True,
        "supports_mlo": True,
        "max_5ghz_width_mhz": None,
        "notes": ["320 MHz works on the 6 GHz band only."],
        "sources": ["https://www.tp-link.com/us/deco-mesh-wifi/product-family/deco-be63/"],
    },
    # Deco BE85 ("BE22000 Tri-Band Whole Home Mesh WiFi 7 System").
    # Source: https://www.tp-link.com/sg/home-networking/deco/deco-be85/
    #   - 6 GHz 11530, 5 GHz 8647, 2.4 GHz 1376 Mbps (802.11be)
    #   - "1x 10 Gbps", "1x 10 Gbps SFP+/RJ45 Combo", "2x 2.5 Gbps" per unit
    #   - MLO and 320 MHz listed ("only available on the 6 GHz band")
    #   - "Wireless and Wired Combined Backhaul"
    "BE85": {
        "name": "Deco BE85",
        "marketing_class": "BE22000",
        "wifi_gen": 7,
        "bands": ["band2_4", "band5", "band6"],
        "max_rates_mbps": {"band6": 11530, "band5": 8647, "band2_4": 1376},
        "ports": "1 x 10 Gbps + 1 x 10 Gbps SFP+/RJ45 combo + 2 x 2.5 Gbps Ethernet ports per unit",
        "port_count": 4,
        "max_port_gbps": 10.0,
        "multi_gig": True,
        "supports_320mhz": True,
        "supports_mlo": True,
        "max_5ghz_width_mhz": None,
        "notes": ["320 MHz works on the 6 GHz band only."],
        "sources": ["https://www.tp-link.com/sg/home-networking/deco/deco-be85/"],
    },
    # Deco BE95 ("BE33000 Quad-Band Whole Home Mesh WiFi 7 System").
    # Source: https://www.tp-link.com/en/home-networking/deco/deco-be95/ (via search)
    #   - 11520 Mbps on EACH of two 6 GHz bands, 8640 Mbps 5 GHz, 1148 Mbps 2.4 GHz
    #   - "1x 10 Gbps RJ45/SFP+ Combo port + 1x 10 Gbps port + 2x 2.5 Gbps ports per unit"
    #   - MLO and 320 MHz listed
    "BE95": {
        "name": "Deco BE95",
        "marketing_class": "BE33000",
        "wifi_gen": 7,
        "bands": ["band2_4", "band5", "band6"],
        "max_rates_mbps": {"band6": 11520, "band5": 8640, "band2_4": 1148},
        "ports": "1 x 10 Gbps RJ45/SFP+ combo + 1 x 10 Gbps + 2 x 2.5 Gbps Ethernet ports per unit",
        "port_count": 4,
        "max_port_gbps": 10.0,
        "multi_gig": True,
        "supports_320mhz": True,
        "supports_mlo": True,
        "max_5ghz_width_mhz": None,
        "notes": ["Quad-band: it has two separate 6 GHz radios."],
        "sources": [
            "https://www.tp-link.com/en/home-networking/deco/deco-be95/",
            "https://static.tp-link.com/upload/product-overview/2024/202406/20240627/Deco%20BE95%20(US)1.0_Datasheet.pdf",
        ],
    },
    # Deco BE25 ("BE5000", dual-band Wi-Fi 7, no 6 GHz).
    # Source: https://www.tp-link.com/en/home-networking/deco/deco-be25/(us) v1/
    #   - "2x 2.5 Gbps" per unit, 2.4 GHz + 5 GHz only, MLO listed, "240 MHz Channel"
    # Source (speeds, via search): 4324 Mbps (5 GHz) + 688 Mbps (2.4 GHz)
    #   https://static.tp-link.com/upload/product-overview/2024/202407/20240723/Deco%20BE25-Datasheet.pdf
    "BE25": {
        "name": "Deco BE25",
        "marketing_class": "BE5000",
        "wifi_gen": 7,
        "bands": ["band2_4", "band5"],
        "max_rates_mbps": {"band6": None, "band5": 4324, "band2_4": 688},
        "ports": "2 x 2.5 Gbps Ethernet ports per unit",
        "port_count": 2,
        "max_port_gbps": 2.5,
        "multi_gig": True,
        "supports_320mhz": False,
        "supports_mlo": True,
        "max_5ghz_width_mhz": 240,
        "notes": ["Dual-band: no 6 GHz radio."],
        "sources": [
            "https://www.tp-link.com/en/home-networking/deco/deco-be25/(us) v1/",
            "https://static.tp-link.com/upload/product-overview/2024/202407/20240723/Deco%20BE25-Datasheet.pdf",
        ],
    },
    # Deco XE75 (AXE5400, Wi-Fi 6E tri-band).
    # Source (via search): "3x Gigabit Ports" per unit; bands 2.4, 5 and 6 GHz.
    #   https://www.tp-link.com/home-networking/deco/deco-xe75/
    # MLO and 320 MHz are Wi-Fi 7 features, so a Wi-Fi 6E model has neither.
    "XE75": {
        "name": "Deco XE75",
        "marketing_class": "AXE5400",
        "wifi_gen": 6,
        "bands": ["band2_4", "band5", "band6"],
        "max_rates_mbps": {"band6": None, "band5": None, "band2_4": None},
        "ports": "3 x Gigabit Ethernet ports per unit",
        "port_count": 3,
        "max_port_gbps": 1.0,
        "multi_gig": False,
        "supports_320mhz": False,
        "supports_mlo": False,
        "max_5ghz_width_mhz": None,
        "notes": ["The XE75 Pro is a different model with a 2.5 Gbps port."],
        "sources": ["https://www.tp-link.com/home-networking/deco/deco-xe75/"],
    },
    # Deco X50 (AX3000, Wi-Fi 6 dual-band).
    # Source (via search): "3x Gigabit Ports, per Deco unit", 2402 Mbps (5 GHz)
    #   + 574 Mbps (2.4 GHz): https://www.tp-link.com/home-networking/deco/deco-x50/
    "X50": {
        "name": "Deco X50",
        "marketing_class": "AX3000",
        "wifi_gen": 6,
        "bands": ["band2_4", "band5"],
        "max_rates_mbps": {"band6": None, "band5": 2402, "band2_4": 574},
        "ports": "3 x Gigabit Ethernet ports per unit",
        "port_count": 3,
        "max_port_gbps": 1.0,
        "multi_gig": False,
        "supports_320mhz": False,
        "supports_mlo": False,
        "max_5ghz_width_mhz": None,
        "notes": ["Other X50 variants (Pro, PoE, Outdoor) have different ports."],
        "sources": ["https://www.tp-link.com/home-networking/deco/deco-x50/"],
    },
}

# Which models are sold under a marketing class. "BE11000" covers two models.
# Sources: the BE65 and BE65 Pro pages above.
MARKETING_CLASSES = {
    "BE33000": ["BE95"],
    "BE22000": ["BE85"],
    "BE11000": ["BE65", "BE65 PRO"],
    "BE10000": ["BE63"],
    "BE5000": ["BE25"],
    "AXE5400": ["XE75"],
    "AX3000": ["X50"],
}


def _compact(text: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", text.upper())


_MODEL_INDEX = {_compact(code): code for code in MODELS}


def _model_key(model) -> str | None:
    if not isinstance(model, str):
        return None
    text = model.upper()
    text = re.sub(r"\(.*?\)", " ", text)               # region tag, e.g. (US)
    text = re.sub(r"\bDECO\b", " ", text)
    text = re.sub(r"\bV\d+(\.\d+)*\b", " ", text)       # hardware version, e.g. V2
    text = re.sub(r"\b\d+\s*-?\s*PACK\b", " ", text)    # "3-pack"
    key = _compact(text)
    return key or None


def model_info(model: str | None) -> dict | None:
    """Return a copy of the spec dict for a Deco model, or None if unknown.

    Accepts "BE65", "Deco BE65", "be65(US)", "BE65 v2", "BE65 Pro" and so on.
    The copy has an extra "code" key with the MODELS key it matched.
    """
    try:
        key = _model_key(model)
        if not key:
            return None
        code = _MODEL_INDEX.get(key)
        if code is None:
            return None
        info = copy.deepcopy(MODELS[code])
        info["code"] = code
        return info
    except Exception:  # never let a lookup break the caller
        return None


# ---------------------------------------------------------------------------
# Where settings live in the Deco app
# ---------------------------------------------------------------------------

# TP-Link's own FAQs say "Features available in Deco may vary by model and
# software version" (https://www.tp-link.com/us/support/faq/1591/).
APP_PATHS_NOTE = "Menu names can differ a bit between Deco app versions and models."

APP_PATHS = {
    # https://www.tp-link.com/us/support/faq/1794/ : "opening the Deco app,
    # navigating to the network map, and tapping on any satellite Deco"
    "network_map": "Deco app → network map (main screen) → tap a Deco",
    # https://community.tp-link.com/us/home/kb/detail/380 :
    # "Launch Deco app -> Tap More -> Tap Advanced -> Tap Fast roaming"
    "fast_roaming": "Deco app → More → Advanced → Fast Roaming",
    # TP-Link staff reply, https://community.tp-link.com/en/home/forum/topic/159101 :
    # "Deco APP>More>Advanced>Beamforming"; some models have no switch (always on).
    "beamforming": "Deco app → More → Advanced → Beamforming",
    # https://community.tp-link.com/en/home/forum/topic/672416 :
    # "Deco APP > Wi-Fi Settings > Enable MLO Network" (Wi-Fi Settings is under More)
    "mlo": "Deco app → More → Wi-Fi Settings → MLO Network",
    # https://www.tp-link.com/support/faq/4420/ : "go to More > IoT Network"
    "iot_network": "Deco app → More → IoT Network",
    # https://www.tp-link.com/us/support/faq/1601 : "More > QoS"
    "qos": "Deco app → More → QoS",
    # https://www.tp-link.com/en/support/faq/2642/ : "More > Internet Connection > IPv6"
    "ipv6": "Deco app → More → Internet Connection → IPv6",
    # https://www.tp-link.com/support/faq/1855/ : "More > Internet Connection >
    # Internet settings", then DNS Address > Manual (Router mode only)
    "dns": "Deco app → More → Internet Connection → Internet Settings → DNS Address → Manual",
    # same FAQ, fallback: "Deco app > More > Advanced > DHCP Server"
    "dns_dhcp": "Deco app → More → Advanced → DHCP Server",
    # https://www.tp-link.com/us/support/faq/1842/ : "More > Advanced > Operation Mode"
    "operation_mode": "Deco app → More → Advanced → Operation Mode",
    # https://www.tp-link.com/us/support/faq/1599/ : "More > System > Update Deco"
    "firmware": "Deco app → More → System → Update Deco",
    # https://www.tp-link.com/us/support/faq/1591/ : "Tap More, then tap Wi-Fi Settings"
    "wifi_settings": "Deco app → More → Wi-Fi Settings",
    # same FAQ: "Tap Advanced, then tap Band"
    "wifi_bands": "Deco app → More → Wi-Fi Settings → Advanced → Band",
    # same FAQ: toggle "Hide this network from Wi-Fi lists" under Advanced
    "hide_network": "Deco app → More → Wi-Fi Settings → Advanced → Hide this network from Wi-Fi lists",
    # https://www.tp-link.com/support/faq/4407/ :
    # "More > Wi-Fi Settings > 2.4G & 5G Wireless Network > Advanced"
    "channel_width": "Deco app → More → Wi-Fi Settings → 2.4G & 5G Wireless Network → Advanced",
    # TP-Link FAQ 3270 (now offline; seen via search): "tap More and select
    # Wi-Fi Settings, then open the 6 GHz Network module". Hedge in user text.
    "six_ghz": "Deco app → More → Wi-Fi Settings → 6 GHz network",
}


# ---------------------------------------------------------------------------
# Ethernet backhaul, cables and MLO facts
# ---------------------------------------------------------------------------

# All from https://www.tp-link.com/us/support/faq/1794/ unless noted.
ETHERNET_BACKHAUL = {
    # "The Ethernet backhaul activates automatically. No additional
    # configuration is needed in the app."
    "automatic": True,
    # "Most switches on the market support Deco's Ethernet backhaul."
    "works_through_switch": True,
    # "If your switch supports loop detection, it may block the port used by
    # Deco. Please turn off the loop detection function on your switch..."
    "switch_loop_detection_tip": "If your switch has loop detection, turn it off, because it can block the Deco's port.",
    # "You can mix wired and wireless backhaul in the same network."
    "mixed_ok": True,
    # Router mode: satellites must connect to the main Deco's LAN port or to a
    # switch attached to it (FAQ 1794 via search summary).
    "router_mode_rule": "In Router mode (the normal setup), plug the other end into the main Deco or a switch connected to it, not into your provider's modem.",
    # "Wireless and Wired Combined Backhaul" on Wi-Fi 7 models, for example
    # https://www.tp-link.com/en/home-networking/deco/deco-be65/v2
    "combined_backhaul_models": ["BE65", "BE85"],
}

# IEEE 802.3bz runs 2.5 Gbps over 100 m of Cat5e and 5 Gbps over Cat6.
# https://en.wikipedia.org/wiki/2.5GBASE-T_and_5GBASE-T
# https://flukenetworks.com/blog/cabling-chronicles/will-my-existing-cable-plant-support-255gbase-t
# IEEE 802.3an 10GBASE-T: Cat6A for the full 100 m; Cat6 only up to about 55 m.
# https://en.wikipedia.org/wiki/10_Gigabit_Ethernet#10GBASE-T
CABLE_FACTS = {
    "cat5e_max_gbps": 2.5,
    "cat6_max_gbps": 5.0,   # at 100 m per 802.3bz; Cat6A or better for 10 Gbps
    "cat6a_max_gbps": 10.0,
    "cat6_10g_max_length_m": 55,
    "max_length_m": 100,
}

# https://community.tp-link.com/en/home/forum/topic/672416
MLO_FACTS = {
    "separate_network_name": True,    # "the network names of the MLO network and the main network need to be separated"
    "default_bands": ["band5", "band6"],  # "operates on 5 GHz+6 GHz by default"
    "security": ["WPA3", "OWE"],      # "Only WPA3 and OWE security are supported"
    "needs_wifi7_client": True,       # client and Deco must both support Wi-Fi 7 and MLO
    # https://www.tp-link.com/us/support/faq/3911/ : "In some cases, MLO
    # performance may be lower than single-band Wi-Fi performance if the client
    # device has limited or partial MLO support."
    "slower_on_some_devices_tip": "Some devices are slower on MLO. If one feels slower, move it back to your main network.",
}

# https://community.tp-link.com/us/home/kb/detail/380 : Fast Roaming uses
# 802.11r; some older clients can't connect when it is on.
# https://www.tp-link.com/ru/support/faq/3039 : turn Fast Roaming off if a
# client fails to connect.
FAST_ROAMING_CAVEAT = "If an older gadget stops connecting after you turn it on, switch it back off."

# Short plain-language explanations used by the UI and the analyzer.
JARGON = {
    "backhaul": "the Wi-Fi (or cable) link the Decos use to talk to each other",
    "mlo": "MLO (Multi-Link Operation) lets a Wi-Fi 7 device use two bands at once",
    "bufferbloat": "extra lag that shows up when your internet line is busy",
    "double_nat": "two routers in a row, each sharing one internet address",
    "dbm": "a signal strength unit; closer to 0 is stronger, so -50 is great and -75 is weak",
    "snr": "how much stronger your signal is than the background noise",
    "dns": "the internet's phone book that turns website names into addresses",
    # https://www.tp-link.com/us/support/faq/1601/ : Deco QoS asks for your
    # Total Bandwidth, then puts chosen activities (Gaming, Video
    # Conferencing) or devices first.
    "qos": "a setting that puts games, calls or chosen devices first when your line is busy",
}
