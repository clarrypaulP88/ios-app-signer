"""Rules engine: turn a Snapshot into a score and a ranked list of fixes.

``analyze(snapshot)`` never raises. Every rule runs inside its own
``try``/``except``, so one broken rule (or one odd value from the Deco) cannot
stop the others. Missing or ``None`` data simply means a rule has nothing to
say.

The output shape is the SPEC "Analysis" dict. Each finding also carries a few
private helper keys while the rules run (``_bn``, ``_fix``, ``_scored``). They
are removed before the result is returned.
"""

from __future__ import annotations

import ipaddress
import math

from .knowledge import (
    APP_PATHS,
    APP_PATHS_NOTE,
    CABLE_FACTS,
    ETHERNET_BACKHAUL,
    FAST_ROAMING_CAVEAT,
    MLO_FACTS,
    model_info,
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "good": 4}
IMPACT_ORDER = {"big": 0, "medium": 1, "small": 2}
PENALTY = {"critical": 30, "high": 15, "medium": 7, "low": 2, "good": 0}
SCORE_MIN = 5
SCORE_MAX = 100

BOTTLENECKS = (
    "internet plan", "wifi signal", "mesh backhaul", "bufferbloat",
    "device", "dns", "none found", "not enough data",
)

_SEV_WEIGHT = {"critical": 1000, "high": 100, "medium": 10, "low": 1, "good": 0}
_IMPACT_WEIGHT = {"big": 3, "medium": 2, "small": 1}
_BN_PRIORITY = ("mesh backhaul", "wifi signal", "internet plan", "bufferbloat", "device", "dns")

_BN_LABEL = {
    "internet plan": "your internet line itself",
    "wifi signal": "your Wi-Fi signal",
    "mesh backhaul": "the link between your Decos (the backhaul)",
    "bufferbloat": "lag when your line is busy (bufferbloat)",
    "device": "this computer's own Wi-Fi or network hardware",
    "dns": "slow website lookups (DNS)",
}

_BAND_LABEL = {"band2_4": "2.4 GHz", "band5": "5 GHz", "band6": "6 GHz"}
_LINK_BAND_LABEL = {"2.4GHz": "2.4 GHz", "5GHz": "5 GHz", "6GHz": "6 GHz"}
_HIGH_BANDS = ("band6", "band5")


# ---------------------------------------------------------------------------
# Small safe helpers
# ---------------------------------------------------------------------------

def _d(value) -> dict:
    return value if isinstance(value, dict) else {}


def _l(value) -> list:
    return value if isinstance(value, list) else []


def _num(value) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        f = float(value)
    elif isinstance(value, str):
        try:
            f = float(value.strip().replace("−", "-"))
        except ValueError:
            return None
    else:
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    return f


def _pos(value) -> float | None:
    f = _num(value)
    return f if f is not None and f > 0 else None


def _nonneg(value) -> float | None:
    f = _num(value)
    return f if f is not None and f >= 0 else None


def _s(value) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


def _bool(value) -> bool | None:
    return value if isinstance(value, bool) else None


def _mac(value) -> str | None:
    text = _s(value)
    if not text:
        return None
    return text.upper().replace("-", ":")


def _fmt(value, digits: int = 0) -> str:
    f = _num(value)
    if f is None:
        return "?"
    if digits <= 0:
        return "%d" % int(round(f))
    return ("%." + str(digits) + "f") % f


def _mbps(value) -> str:
    f = _num(value)
    if f is None:
        return "? Mbps"
    if f >= 10:
        return "%d Mbps" % int(round(f))
    return "%.1f Mbps" % f


def _pct(value) -> str:
    f = _num(value)
    return "?" if f is None else "%d%%" % int(round(f))


def _q(name: str) -> str:
    return "'%s'" % name


def _join(items: list) -> str:
    items = [str(i) for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def _verb(items: list, singular: str, plural: str) -> str:
    return singular if len(items) == 1 else plural


def _node_name(node: dict) -> str:
    return _s(node.get("name")) or _s(node.get("mac")) or "a Deco"


def _finding(fid, severity, category, title, what, how, impact, evidence,
             bottleneck=None, fix=None, scored=True) -> dict:
    steps = [str(s) for s in (how or []) if s]
    if any("Deco app →" in s for s in steps):
        steps.append(APP_PATHS_NOTE)
    return {
        "id": fid,
        "severity": severity,
        "category": category,
        "title": title,
        "what_it_means": what,
        "how_to_fix": steps,
        "impact": impact,
        "evidence": evidence,
        "_bn": bottleneck,
        "_fix": fix,
        "_scored": scored,
    }


def _path(key: str) -> str:
    return APP_PATHS.get(key, "the Deco app")


# ---------------------------------------------------------------------------
# Context: a cleaned-up view of the snapshot that every rule shares
# ---------------------------------------------------------------------------

class _Ctx(object):
    def __init__(self, snapshot):
        s = snapshot if isinstance(snapshot, dict) else {}
        self.settings = _d(s.get("settings"))
        deco = s.get("deco")
        self.deco = deco if isinstance(deco, dict) else None
        self.deco_error = _s(s.get("deco_error"))
        d = self.deco or {}
        self.nodes = [n for n in _l(d.get("nodes")) if isinstance(n, dict)]
        self.clients = [c for c in _l(d.get("clients")) if isinstance(c, dict)]
        self.wifi = _d(d.get("wifi"))
        self.bands = _d(self.wifi.get("bands"))
        self.wan = _d(d.get("wan"))
        self.perf = _d(d.get("performance"))

        link = s.get("link")
        self.link = link if isinstance(link, dict) else None
        latency = s.get("latency")
        self.latency = latency if isinstance(latency, dict) else None
        speed = s.get("speed")
        self.speed = speed if isinstance(speed, dict) else None
        dns = s.get("dns")
        self.dns = dns if isinstance(dns, dict) else None
        self.history = [h for h in _l(s.get("history")) if isinstance(h, dict)]

        self.plan_down = _pos(self.settings.get("plan_down_mbps"))
        self.plan_up = _pos(self.settings.get("plan_up_mbps"))

        main = None
        for n in self.nodes:
            if n.get("role") == "main":
                main = n
                break
        if main is None and self.nodes:
            main = self.nodes[0]
        self.main = main
        self.satellites = [n for n in self.nodes if n is not main and n.get("role") != "main"]

        code = None
        for n in ([main] if main else []) + self.nodes:
            code = _s(n.get("model"))
            if code:
                break
        self.model_code = code
        self.model = model_info(code) if code else None

        # Link
        lk = self.link or {}
        ltype = _s(lk.get("type"))
        self.link_rssi = _num(lk.get("rssi_dbm"))
        self.link_type = ltype if ltype in ("wifi", "ethernet") else None
        if self.link_type is None and self.link_rssi is not None:
            self.link_type = "wifi"
        self.link_band = _s(lk.get("band"))
        self.link_tx = _pos(lk.get("tx_rate_mbps"))
        self.link_rx = _pos(lk.get("rx_rate_mbps"))
        rates = [r for r in (self.link_tx, self.link_rx) if r is not None]
        self.link_rate = max(rates) if rates else None

        # Latency
        lat = self.latency or {}
        gw = lat.get("gateway")
        self.gateway = gw if isinstance(gw, dict) else None
        self.gw_median = _num(_d(self.gateway).get("median_ms"))
        self.gw_jitter = _num(_d(self.gateway).get("jitter_ms"))
        self.gw_loss = _num(_d(self.gateway).get("loss_pct")) if self.gateway else None
        self.internet_targets = [t for t in _l(lat.get("internet")) if isinstance(t, dict)]

        # Speed
        sp = self.speed or {}
        self.down = _nonneg(sp.get("down_mbps"))
        self.up = _nonneg(sp.get("up_mbps"))
        # The download already reaches the plan (>= 90%): the plan is the ceiling.
        self.plan_reached = bool(self.plan_down and self.down is not None
                                 and self.down >= 0.9 * self.plan_down)
        # On a cable, measure.wifi_link copies the port's link speed into
        # tx/rx_rate_mbps. A cable link below the plan (or stuck at 100 Mbps)
        # caps every test, so don't blame Wi-Fi or the provider for it.
        self.eth_slow = False
        if self.link_type == "ethernet" and self.link_rate is not None:
            if self.plan_down:
                self.eth_slow = not self.plan_reached and self.link_rate < 0.95 * self.plan_down
            else:
                self.eth_slow = self.link_rate <= 100

        # DNS
        self.dns_median = _num(_d(self.dns).get("median_ms"))

        # Coverage
        self.cov_deco = self.deco is not None
        self.cov_link = self.link is not None and self.link_type is not None
        internet_medians = [_num(t.get("median_ms")) for t in self.internet_targets]
        self.cov_latency = self.gw_median is not None or any(m is not None for m in internet_medians)
        self.cov_speed = self.down is not None or self.up is not None
        self.cov_dns = self.dns_median is not None
        self.rooms = self._rooms()

        # Shared mesh view
        self.sat_status = {}
        for n in self.satellites:
            try:
                self.sat_status[id(n)] = _sat_backhaul(n)
            except Exception:
                self.sat_status[id(n)] = {"level": None}
        self.mesh_trouble = any(st.get("level") in ("high", "medium") for st in self.sat_status.values())
        for n in self.satellites:
            if n.get("backhaul") == "wireless" and _sat_best_rate(n) is not None \
                    and _sat_best_rate(n) < 400:
                self.mesh_trouble = True

    def _rooms(self) -> list:
        latest = {}
        order = []
        for h in self.history:
            room = _s(h.get("room"))
            if not room:
                continue
            key = room.lower()
            if key not in latest:
                order.append(key)
            latest[key] = h
        return [latest[k] for k in order]

    def has_band(self, band: str) -> bool | None:
        if isinstance(self.bands.get(band), dict):
            return True
        if self.model:
            return band in _l(self.model.get("bands"))
        return None

    def band_cfg(self, band: str) -> dict:
        return _d(self.bands.get(band))


def _sat_best_rate(node: dict) -> float | None:
    rates = []
    for key in ("rx_rate_mbps", "tx_rate_mbps"):
        values = _d(node.get(key))
        for band in _HIGH_BANDS:
            r = _pos(values.get(band))
            if r is not None:
                rates.append(r)
    return max(rates) if rates else None


def _sat_backhaul(node: dict) -> dict:
    """How healthy is one satellite's wireless backhaul?

    Returns {"level": "high"|"medium"|"ok"|None, "reason": ..., "band": ...,
    "dbm": ..., "bars": ...}. level None means we can't tell (or it's wired).
    """
    if node.get("backhaul") == "wired":
        return {"level": None, "reason": "wired"}
    sig = _d(node.get("signal_dbm"))
    bars = _d(node.get("signal_bars"))
    bands = [b for b in _l(node.get("backhaul_bands")) if isinstance(b, str)]

    hi_dbm = {}
    for b in _HIGH_BANDS:
        v = _num(sig.get(b))
        if v is not None and v < 0:
            hi_dbm[b] = v
    hi_bars = {}
    for b in _HIGH_BANDS:
        v = _num(bars.get(b))
        if v is not None and v > 0:
            hi_bars[b] = int(v)
    low_dbm = _num(sig.get("band2_4"))
    low_bars = _num(bars.get("band2_4"))
    has_low = (low_dbm is not None and low_dbm < 0) or (low_bars is not None and low_bars > 0)

    only_2g = False
    if bands:
        only_2g = bands == ["band2_4"]
    elif has_low and not hi_dbm and not hi_bars:
        only_2g = True
    if only_2g:
        return {"level": "high", "reason": "2g", "band": "band2_4", "dbm": low_dbm,
                "bars": int(low_bars) if low_bars is not None else None}

    if hi_dbm:
        band = max(hi_dbm, key=lambda b: hi_dbm[b])
        best = hi_dbm[band]
        if best < -70:
            level = "high"
        elif best < -65:
            level = "medium"
        else:
            level = "ok"
        return {"level": level, "reason": "dbm", "band": band, "dbm": best, "bars": None}
    if hi_bars:
        band = max(hi_bars, key=lambda b: hi_bars[b])
        best_bars = hi_bars[band]
        level = "high" if best_bars <= 2 else "ok"
        return {"level": level, "reason": "bars", "band": band, "dbm": None, "bars": best_bars}
    return {"level": None, "reason": "unknown"}


def _sat_signal_text(node: dict, st: dict) -> str:
    band = _BAND_LABEL.get(st.get("band") or "", "?")
    if st.get("dbm") is not None:
        return "%s: %s dBm on %s" % (_q(_node_name(node)), _fmt(st["dbm"]), band)
    if st.get("bars") is not None:
        return "%s: %d bars on %s" % (_q(_node_name(node)), st["bars"], band)
    return "%s: signal on %s" % (_q(_node_name(node)), band)


# ---------------------------------------------------------------------------
# Rules. Each takes the context and returns a list of findings.
# ---------------------------------------------------------------------------

def rule_units_offline(ctx: _Ctx) -> list:
    out = []
    inet_first = False
    offline = [n for n in ctx.nodes if n.get("online") is False]
    if offline:
        names = [_q(_node_name(n)) for n in offline]
        main_down = ctx.main is not None and ctx.main in offline
        if len(offline) == 1:
            title = "Your %s Deco is offline" % names[0]
        else:
            title = "%d of your Decos are offline" % len(offline)
        what = ("The mesh can't reach %s right now. "
                "Devices near it lose Wi-Fi or fall back to a far-away Deco." % _join(names))
        how = ["Check that %s has power and its light is on." % _join(names)]
        if main_down:
            # The main Deco hangs off the modem by cable, so placement isn't the issue.
            what += " Because it's the main Deco, the whole network may be down."
            how.append("Check the cable between your provider's modem and the main Deco.")
            fix = "get your main Deco back online (check its power and the cable to your modem)"
        else:
            how.append("If it was moved, bring it a bit closer to another Deco.")
            fix = "get your %s Deco back online (check its power and placement)" % names[0]
        how.extend([
            "Unplug it for 10 seconds, plug it back in, and wait 2 minutes.",
            "Check it in %s." % _path("network_map"),
        ])
        out.append(_finding(
            "deco_offline", "critical", "mesh", title, what, how,
            "big",
            "; ".join("%s status: offline" % _q(_node_name(n)) for n in offline),
            bottleneck="mesh backhaul",
            fix=fix,
        ))

    no_inet = [n for n in ctx.nodes if n.get("online") is not False and n.get("internet_online") is False]
    if no_inet:
        main_no = ctx.main is not None and ctx.main in no_inet
        names = [_q(_node_name(n)) for n in no_inet]
        if main_no:
            title = "Your main Deco has no internet"
            what = ("The main Deco is on, but it can't reach the internet. "
                    "So nothing in your home can get online.")
            how = [
                "Check the cable between your provider's modem and the main Deco.",
                "Restart the modem (unplug it for 30 seconds), then the main Deco.",
                "Check your provider's status page or app for an outage.",
            ]
            fix = "restart your modem and check the cable to the main Deco"
            bn = "internet plan"
            inet_first = True
        else:
            title = "%s %s no internet" % (_join(names), _verb(names, "says it has", "say they have"))
            what = ("%s %s on, but the path to the internet is broken. "
                    "That usually means the link to the main Deco has a problem."
                    % (_join(names), _verb(names, "is", "are")))
            how = [
                "Move %s a bit closer to the main Deco." % _join(names),
                "If it's on a cable, check both ends and try another cable.",
                "Restart it by unplugging it for 10 seconds.",
            ]
            fix = "fix the link from %s to the main Deco" % names[0]
            bn = "mesh backhaul"
        inet = _finding(
            "deco_internet_offline", "critical", "internet", title, what, how, "big",
            "; ".join("%s internet: offline" % _q(_node_name(n)) for n in no_inet),
            bottleneck=bn, fix=fix,
        )
        if inet_first:
            out.insert(0, inet)
        else:
            out.append(inet)

    if ctx.nodes and not offline and not no_inet and all(n.get("online") is True for n in ctx.nodes):
        out.append(_finding(
            "all_decos_online", "good", "mesh",
            "All %d of your Decos are online" % len(ctx.nodes),
            "Every Deco in your mesh is connected and working.",
            ["Nothing to do here."],
            "small",
            "%d of %d Decos online" % (len(ctx.nodes), len(ctx.nodes)),
        ))
    return out


def rule_backhaul_signal(ctx: _Ctx) -> list:
    out = []
    weak = []
    only_2g = []
    ok = []
    for n in ctx.satellites:
        if n.get("online") is False:
            continue
        st = ctx.sat_status.get(id(n)) or {}
        level = st.get("level")
        if level is None:
            continue
        if st.get("reason") == "2g":
            only_2g.append((n, st))
        elif level in ("high", "medium"):
            weak.append((n, st))
        else:
            ok.append((n, st))

    if weak:
        severity = "high" if any(st["level"] == "high" for _, st in weak) else "medium"
        weak.sort(key=lambda p: (0 if p[1]["level"] == "high" else 1))
        names = [_q(_node_name(n)) for n, _ in weak]
        if len(weak) == 1:
            title = "Your %s Deco has a weak link back to the main one" % names[0]
        else:
            title = "%d of your Decos have a weak link back to the main one" % len(weak)
        what = ("Backhaul is the Wi-Fi link the Decos use to talk to each other. "
                "%s %s the next Deco only weakly. "
                "So every device connected there gets slower speed. "
                "Signal is measured in dBm, and closer to 0 is stronger."
                % (_join(names), _verb(names, "hears", "hear")))
        how = [
            "Move %s closer to the Deco it links to." % _join(names),
            "A good spot is about halfway between the main Deco and the area that needs Wi-Fi.",
            "Keep Decos in the open and up high, not in a cupboard, behind a TV or on the floor.",
            "Best fix: connect it with an Ethernet cable (see the Ethernet backhaul tip).",
            "Check the result in %s." % _path("network_map"),
        ]
        evidence = "; ".join(_sat_signal_text(n, st) for n, st in weak) + \
            " (aim for -65 dBm or better, or 3+ bars)"
        out.append(_finding(
            "satellite_wireless_backhaul_weak", severity, "mesh", title, what, how, "big", evidence,
            bottleneck="mesh backhaul",
            fix="move %s closer to the main Deco or connect it with an Ethernet cable" % names[0],
        ))

    if only_2g:
        names = [_q(_node_name(n)) for n, _ in only_2g]
        title = "%s %s to the other Decos over slow 2.4 GHz only" % (_join(names), _verb(names, "talks", "talk"))
        what = ("Backhaul is the Wi-Fi link the Decos use to talk to each other. "
                "%s %s only the slow 2.4 GHz band for it. "
                "That usually means the Deco is too far away to hear the faster 5 or 6 GHz bands."
                % (_join(names), _verb(names, "is using", "are using")))
        out.append(_finding(
            "satellite_backhaul_2g_only", "high", "mesh", title, what,
            [
                "Move %s closer to the main Deco, so it can link over 5 or 6 GHz." % _join(names),
                "Or connect it with an Ethernet cable for a full-speed link.",
                "Check the result in %s." % _path("network_map"),
            ],
            "big",
            "; ".join("%s backhaul: 2.4 GHz only" % _q(_node_name(n)) for n, _ in only_2g),
            bottleneck="mesh backhaul",
            fix="move %s closer to the main Deco or wire it with Ethernet" % names[0],
        ))

    slow_link = any(n.get("online") is not False and n.get("backhaul") == "wireless"
                    and _sat_best_rate(n) is not None and _sat_best_rate(n) < 400
                    for n in ctx.satellites)
    if ok and not weak and not only_2g and not slow_link:
        out.append(_finding(
            "satellite_backhaul_strong", "good", "mesh",
            "Your Decos hear each other well",
            "Backhaul is the Wi-Fi link the Decos use to talk to each other. "
            "Every wireless satellite has a strong signal back to the mesh.",
            ["Keep the Decos where they are. A cable is still the best upgrade if you can run one."],
            "small",
            "; ".join(_sat_signal_text(n, st) for n, st in ok),
        ))
    return out


def rule_ethernet_backhaul(ctx: _Ctx) -> list:
    out = []
    sats = [n for n in ctx.satellites if n.get("online") is not False]
    wireless = [n for n in sats if n.get("backhaul") == "wireless"]
    wired = [n for n in sats if n.get("backhaul") == "wired"]
    if wireless:
        names = [_q(_node_name(n)) for n in wireless]
        trouble = False
        for n in wireless:
            st = ctx.sat_status.get(id(n)) or {}
            rate = _sat_best_rate(n)
            if st.get("level") in ("high", "medium") or (rate is not None and rate < 400):
                trouble = True
        severity = "medium" if trouble else "low"
        if len(wireless) == 1:
            title = "Connect your %s Deco with an Ethernet cable" % names[0]
        else:
            title = "Connect your satellite Decos with Ethernet cables"
        what = ("Right now %s %s Wi-Fi to talk to the main Deco. "
                "That link is called the backhaul, and it shares airtime with your devices. "
                "A cable gives a full-speed, steady link and frees up Wi-Fi for everything else."
                % (_join(names), _verb(names, "uses", "use")))
        how = ["Run an Ethernet cable to %s. %s" % (_join(names), ETHERNET_BACKHAUL["router_mode_rule"])]
        m = ctx.model
        port_gbps = _num(m.get("max_port_gbps")) if m else None
        if port_gbps and port_gbps >= 2.5:
            how.append("Your %s has %s, so a cable link can run at up to %s Gbps. "
                       "Use the 2.5 Gbps or faster ports on both ends."
                       % (m.get("name"), m.get("ports"), _fmt(port_gbps, 1).replace(".0", "")))
            if port_gbps >= CABLE_FACTS["cat6a_max_gbps"]:
                how.append("For the full 10 Gbps, use Cat6A cable. Plain Cat6 only manages 10 Gbps on "
                           "short runs (up to about %d m), and Cat5e tops out at 2.5 Gbps."
                           % CABLE_FACTS["cat6_10g_max_length_m"])
            else:
                how.append("Cat6 cable is a safe pick. Cat5e also handles 2.5 Gbps up to 100 m.")
        else:
            how.append("Any Cat5e or Cat6 network cable works. Cat6 is a safe pick.")
        how.append("A network switch in between is fine. %s" % ETHERNET_BACKHAUL["switch_loop_detection_tip"])
        how.append("You don't need to change any setting. The Deco switches to the cable by itself.")
        how.append("You can mix: wire the Decos you can and leave the rest on Wi-Fi.")
        how.append("Check it in %s. It should show a wired (Ethernet) link." % _path("network_map"))
        parts = []
        for n in wireless:
            st = ctx.sat_status.get(id(n)) or {}
            bits = [_BAND_LABEL.get(b, b) for b in _l(n.get("backhaul_bands")) if isinstance(b, str)]
            text = "%s: wireless backhaul" % _q(_node_name(n))
            if bits:
                text += " (%s" % "/".join(bits)
                if st.get("dbm") is not None:
                    text += ", %s dBm" % _fmt(st["dbm"])
                text += ")"
            parts.append(text)
        out.append(_finding(
            "use_ethernet_backhaul", severity, "mesh", title, what, how, "big", "; ".join(parts),
            bottleneck="mesh backhaul",
            fix="connect %s to the main Deco with an Ethernet cable" % names[0],
        ))
    elif sats and len(wired) == len(sats):
        out.append(_finding(
            "ethernet_backhaul_all", "good", "mesh",
            "All your satellite Decos use a cable",
            "Your Decos talk to each other over Ethernet. "
            "That's the fastest and steadiest way to build a mesh.",
            ["Nothing to fix. This is the best setup."],
            "small",
            "; ".join("%s: wired backhaul" % _q(_node_name(n)) for n in wired),
        ))
    return out


def rule_daisy_chain(ctx: _Ctx) -> list:
    sat_by_mac = {}
    for n in ctx.satellites:
        mac = _mac(n.get("mac"))
        if mac:
            sat_by_mac[mac] = n
    chains = []
    for n in ctx.satellites:
        if n.get("online") is False or n.get("backhaul") == "wired":
            continue
        parent = _mac(n.get("parent_mac"))
        if parent and parent in sat_by_mac and parent != _mac(n.get("mac")):
            if sat_by_mac[parent].get("backhaul") == "wired":
                # The parent is cabled to the mesh, so this is only ONE Wi-Fi
                # hop. That's as good as linking to the main Deco directly.
                continue
            chains.append((n, sat_by_mac[parent]))
    if not chains:
        return []
    child, parent = chains[0]
    cname, pname = _q(_node_name(child)), _q(_node_name(parent))
    if len(chains) == 1:
        title = "%s connects through %s instead of the main Deco" % (cname, pname)
    else:
        title = "%d of your Decos connect through another satellite" % len(chains)
    what = ("%s reaches the main Deco by going through %s first. "
            "Each extra Wi-Fi hop roughly halves the speed. "
            "So devices on %s get the smallest share." % (cname, pname, cname))
    return [_finding(
        "satellite_daisy_chain", "medium", "mesh", title, what,
        [
            "Move %s (or %s) so %s can hear the main Deco directly." % (cname, pname, cname),
            "Or connect %s or %s with an Ethernet cable to remove the slow hop." % (pname, cname),
            "Check how each Deco connects in %s." % _path("network_map"),
        ],
        "medium",
        "; ".join("%s links to %s (a satellite), not the main Deco" % (_q(_node_name(c)), _q(_node_name(p)))
                  for c, p in chains),
        bottleneck="mesh backhaul",
        fix="move %s so it links straight to the main Deco" % cname,
    )]


def rule_backhaul_link_rate(ctx: _Ctx) -> list:
    slow = []
    for n in ctx.satellites:
        if n.get("online") is False or n.get("backhaul") != "wireless":
            continue
        rate = _sat_best_rate(n)
        if rate is not None and rate < 400:
            slow.append((n, rate))
    if not slow:
        return []
    slow.sort(key=lambda p: p[1])
    node, rate = slow[0]
    name = _q(_node_name(node))
    if len(slow) == 1:
        title = "The link to your %s Deco is running slow" % name
    else:
        title = "The links to %d of your Decos are running slow" % len(slow)
    what = ("The Wi-Fi link between %s and the Deco it connects to tops out at %s. "
            "Every device on %s has to share that. "
            "A healthy 5 or 6 GHz link between Decos is usually much faster." % (name, _mbps(rate), name))
    return [_finding(
        "satellite_backhaul_slow_link", "medium", "mesh", title, what,
        [
            "Move %s a little closer to the Deco it links to, with fewer walls in between." % name,
            "Or connect it with an Ethernet cable for a full-speed link.",
            "Check the link in %s." % _path("network_map"),
        ],
        "medium",
        "; ".join("%s: best link rate %s on 5/6 GHz" % (_q(_node_name(n)), _mbps(r)) for n, r in slow),
        bottleneck="mesh backhaul",
        fix="move %s closer to the main Deco or wire it with Ethernet" % name,
    )]


def rule_firmware(ctx: _Ctx) -> list:
    groups = {}
    for n in ctx.nodes:
        fw = _s(n.get("fw_version"))
        if not fw:
            continue
        model = (_s(n.get("model")) or "?").upper()
        groups.setdefault(model, {}).setdefault(" ".join(fw.split()), []).append(_node_name(n))
    mixed = {m: v for m, v in groups.items() if len(v) > 1}
    if not mixed:
        return []
    parts = []
    for model, versions in mixed.items():
        for fw, names in versions.items():
            parts.append("%s on %s" % (_join([_q(x) for x in names]), fw))
    return [_finding(
        "firmware_mismatch", "low", "settings",
        "Your Decos are running different firmware",
        "Firmware is the software inside each Deco. "
        "Decos of the same model work best when they all run the same, latest version.",
        [
            "Go to %s and install any update." % _path("firmware"),
            "Updates restart the Decos, so pick a time when nobody is gaming or on a call.",
        ],
        "small",
        "; ".join(parts),
        fix="update all your Decos to the same firmware",
    )]


def rule_main_busy(ctx: _Ctx) -> list:
    cpu = _num(ctx.perf.get("cpu_pct"))
    mem = _num(ctx.perf.get("mem_pct"))
    if not ((cpu is not None and cpu > 80) or (mem is not None and mem > 90)):
        return []
    return [_finding(
        "main_deco_busy", "medium", "mesh",
        "Your main Deco is working very hard",
        "The main Deco's processor or memory is nearly full. "
        "That can add lag and slow things down for everyone.",
        [
            "Restart the main Deco: unplug it for 10 seconds, then plug it back in.",
            "Check for a firmware update in %s." % _path("firmware"),
            "If it stays this high, run this check again later to see if it was a short spike.",
        ],
        "medium",
        "CPU %s, memory %s" % (_pct(cpu), _pct(mem)),
        fix="restart your main Deco and update its firmware",
    )]


def rule_clients_on_2g(ctx: _Ctx) -> list:
    # Gadgets already on the IoT network are meant to be on 2.4 GHz, so leave
    # them out: they are not "stuck" there.
    wireless = [c for c in ctx.clients
                if c.get("online") is not False and c.get("band") in ("band2_4", "band5", "band6")
                and str(c.get("interface") or "").lower() != "iot"]
    if len(wireless) < 5:
        return []
    on_2g = [c for c in wireless if c.get("band") == "band2_4"]
    share = 100.0 * len(on_2g) / len(wireless)
    if share <= 40:
        return []
    how = [
        "Look at the device list in the Deco app. Phones and laptops on 2.4 GHz are usually far from a Deco.",
        "Move closer, or move a satellite nearer to where those devices are used.",
    ]
    iot = _bool(ctx.wifi.get("iot_enabled"))
    if iot is True:
        how.append("Your IoT network is already on, so put smart-home gadgets on it.")
    else:
        how.append("Give smart-home gadgets their own IoT network: %s (if your app shows it)." % _path("iot_network"))
    return [_finding(
        "many_clients_on_2g", "low", "devices",
        "Lots of your devices are on 2.4 GHz",
        "2.4 GHz is the slower band that reaches further. "
        "Smart plugs, bulbs and cameras often only use 2.4 GHz, and that's fine. "
        "But phones and laptops stuck on 2.4 GHz usually mean they're far from a Deco.",
        how,
        "small",
        "%d of %d Wi-Fi devices (%s) are on 2.4 GHz" % (len(on_2g), len(wireless), _pct(share)),
        fix="get phones and laptops closer to a Deco so they use 5 or 6 GHz",
    )]


def rule_client_balance(ctx: _Ctx) -> list:
    # deco_client sets errors["client_list_per_node"] when it couldn't tell
    # which Deco some devices use: the per-Deco counts are then incomplete.
    if _d(_d(ctx.deco).get("errors")).get("client_list_per_node"):
        return []
    # An offline Deco has 0 devices for an obvious reason; deco_offline covers it.
    nodes = [n for n in ctx.nodes if n.get("online") is not False]
    if len(nodes) < 3:
        return []
    counts = []
    for n in nodes:
        c = _num(n.get("client_count"))
        counts.append((n, int(c) if c is not None and c >= 0 else 0))
    total = sum(c for _, c in counts)
    if total < 8:
        return []
    busy = max(counts, key=lambda p: p[1])
    quiet = min(counts, key=lambda p: p[1])
    if busy[1] / float(total) <= 0.65 or quiet[1] / float(total) >= 0.15:
        return []
    bname, qname = _q(_node_name(busy[0])), _q(_node_name(quiet[0]))
    return [_finding(
        "client_load_unbalanced", "low", "mesh",
        "%s is doing most of the work" % bname,
        "%s has %d of your %d devices, while %s has only %d. "
        "That usually means a Deco sits where few people use Wi-Fi." % (bname, busy[1], total, qname, quiet[1]),
        [
            "Move %s closer to where people actually use their phones and laptops." % qname,
            "A good spot is about halfway between the main Deco and the area with weak Wi-Fi.",
        ],
        "small",
        "; ".join("%s: %d (%s)" % (_q(_node_name(n)), c, _pct(100.0 * c / total)) for n, c in counts),
        bottleneck="wifi signal",
        fix="move %s closer to where people use Wi-Fi" % qname,
    )]


def rule_bands_disabled(ctx: _Ctx) -> list:
    out = []
    b5 = ctx.band_cfg("band5")
    if b5.get("enabled") is False:
        out.append(_finding(
            "band_5ghz_off", "high", "settings",
            "Your 5 GHz Wi-Fi is turned off",
            "5 GHz is the fast band that most phones and laptops use. "
            "With it off, everything gets squeezed onto the slow 2.4 GHz band.",
            ["Go to %s and choose 2.4 GHz and 5 GHz." % _path("wifi_bands")],
            "big",
            "5 GHz band: off",
            bottleneck="wifi signal",
            fix="turn 5 GHz back on in the Deco app",
        ))
    b6 = ctx.band_cfg("band6")
    if b6.get("enabled") is False and ctx.has_band("band6"):
        model = ctx.model.get("name") if ctx.model else "Deco"
        out.append(_finding(
            "band_6ghz_off", "medium", "settings",
            "Your 6 GHz Wi-Fi is turned off",
            "6 GHz is the newest and least crowded band. "
            "Newer phones and laptops use it for top speed. "
            "Your %s has it, but it's switched off." % model,
            [
                "Turn on the 6 GHz network in %s (look for the 6 GHz part)." % _path("six_ghz"),
                "Older devices that can't use 6 GHz will just stay on 5 GHz.",
            ],
            "medium",
            "6 GHz band: off",
            bottleneck="wifi signal",
            fix="turn on 6 GHz in the Deco app",
        ))
    return out


def rule_channel_width(ctx: _Ctx) -> list:
    out = []
    b5 = ctx.band_cfg("band5")
    w5 = _pos(b5.get("width_mhz"))
    if b5 and b5.get("enabled") is not False and w5 is not None and w5 < 80:
        out.append(_finding(
            "narrow_5ghz_channel", "medium", "settings",
            "Your 5 GHz channel is narrow (%s MHz)" % _fmt(w5),
            "Channel width is like the number of lanes on a road. Wider means more speed. "
            "5 GHz at %s MHz leaves a lot of speed unused, and 80 MHz or more is normal." % _fmt(w5),
            [
                "Go to %s, tap 5GHz Network and set the width to 80 MHz or 160 MHz." % _path("channel_width"),
                "If devices start dropping out, go back one size.",
            ],
            "medium",
            "5 GHz channel width: %s MHz" % _fmt(w5),
            bottleneck="wifi signal",
            fix="set 5 GHz to 80 MHz or wider in the Deco app",
        ))
    b6 = ctx.band_cfg("band6")
    w6 = _pos(b6.get("width_mhz"))
    if b6 and b6.get("enabled") is not False and w6 is not None and w6 < 160:
        extra = ""
        if ctx.model and ctx.model.get("supports_320mhz"):
            extra = " Your %s can even use 320 MHz there." % ctx.model.get("name")
        out.append(_finding(
            "narrow_6ghz_channel", "low", "settings",
            "Your 6 GHz channel could be wider",
            "Channel width is like the number of lanes on a road. "
            "6 GHz has lots of free space, so 160 MHz is normal there.%s" % extra,
            [
                "Look for the channel width in %s and choose 160 MHz or 320 MHz if offered." % _path("six_ghz"),
                "Some countries don't allow 320 MHz, so it may not show up.",
            ],
            "small",
            "6 GHz channel width: %s MHz" % _fmt(w6),
            fix="use a 160 MHz or wider channel on 6 GHz",
        ))
    b2 = ctx.band_cfg("band2_4")
    w2 = _pos(b2.get("width_mhz"))
    if b2 and b2.get("enabled") is not False and w2 is not None and int(w2) == 40:
        out.append(_finding(
            "wide_2g_channel", "low", "settings",
            "2.4 GHz is set to a 40 MHz channel",
            "2.4 GHz has very little room. "
            "At 40 MHz it overlaps more with your neighbours' Wi-Fi. "
            "20 MHz is often steadier in crowded areas like apartments.",
            [
                "Go to %s, tap 2.4GHz Network and try 20 MHz." % _path("channel_width"),
                "Only worth doing if 2.4 GHz gadgets drop out or feel slow.",
            ],
            "small",
            "2.4 GHz channel width: 40 MHz",
            fix="try a 20 MHz channel on 2.4 GHz",
        ))
    b5_on = b5.get("enabled") is not False
    b6_on = not b6 or b6.get("enabled") is not False
    if not out and b5_on and b6_on and w5 is not None and w5 >= 80 and (w6 is None or w6 >= 160):
        bits = ["5 GHz %s MHz" % _fmt(w5)]
        if w6 is not None:
            bits.append("6 GHz %s MHz" % _fmt(w6))
        out.append(_finding(
            "channel_widths_ok", "good", "settings",
            "Your Wi-Fi channels are nice and wide",
            "Channel width is like the number of lanes on a road. Yours are set wide for speed.",
            ["Nothing to fix here."],
            "small",
            ", ".join(bits),
        ))
    return out


def rule_mlo(ctx: _Ctx) -> list:
    mlo = _bool(ctx.wifi.get("mlo_enabled"))
    if mlo is None:
        return []
    if ctx.model and ctx.model.get("supports_mlo") is False:
        return []
    if mlo is False:
        return [_finding(
            "mlo_off", "low", "settings",
            "MLO is turned off",
            "MLO (Multi-Link Operation) means a Wi-Fi 7 device can use two bands at once. "
            "That can give more speed and steadier gaming. "
            "Only Wi-Fi 7 phones and laptops can use it.",
            [
                "Turn it on in %s." % _path("mlo"),
                "Deco gives the MLO network its own name. Join it with your Wi-Fi 7 devices only.",
                "It uses WPA3 security, so older gadgets should stay on your main network.",
                MLO_FACTS["slower_on_some_devices_tip"],
            ],
            "small",
            "MLO network: off",
            fix="turn on the MLO network for your Wi-Fi 7 devices",
        )]
    return [_finding(
        "mlo_on", "good", "settings",
        "MLO is on",
        "MLO (Multi-Link Operation) means a Wi-Fi 7 device can use two bands at once. "
        "Your Wi-Fi 7 devices can use it now.",
        ["Connect your Wi-Fi 7 devices to the MLO network to use it."],
        "small",
        "MLO network: on",
    )]


def rule_network_names(ctx: _Ctx) -> list:
    out = []
    hidden = [b for b in ("band2_4", "band5", "band6")
              if ctx.band_cfg(b).get("hidden") is True and ctx.band_cfg(b).get("enabled") is not False]
    if hidden:
        out.append(_finding(
            "hidden_network", "low", "settings",
            "Your Wi-Fi name is hidden",
            "Hiding the name doesn't make your Wi-Fi safer. "
            "It can make devices slower to switch between Decos as you walk around. "
            "A strong password is what keeps people out.",
            ["Switch this off: %s." % _path("hide_network")],
            "small",
            "Hidden on: %s" % ", ".join(_BAND_LABEL[b] for b in hidden),
            fix="stop hiding your Wi-Fi name",
        ))
    same = _bool(ctx.wifi.get("same_ssid_all_bands"))
    if same is False:
        out.append(_finding(
            "split_network_names", "low", "settings",
            "Your Wi-Fi bands have different names",
            "Deco is built to use one name for all bands. "
            "Then it can move each device to the best band and Deco by itself. "
            "Separate names stop that from working.",
            [
                "In %s, give 2.4, 5 and 6 GHz the same name and password." % _path("wifi_settings"),
                "The MLO network is the one exception, because Deco always gives it its own name.",
            ],
            "small",
            "Not all bands share one network name",
            fix="use one Wi-Fi name for all bands",
        ))
    if not out and same is True and not hidden:
        out.append(_finding(
            "network_names_ok", "good", "settings",
            "One visible Wi-Fi name for all bands",
            "Your bands share one name, so Deco can steer each device to the best band and Deco.",
            ["Nothing to fix here."],
            "small",
            "Same name on all bands, not hidden",
        ))
    return out


def rule_nat(ctx: _Ctx) -> list:
    out = []
    double = _bool(ctx.wan.get("double_nat"))
    cgnat = _bool(ctx.wan.get("cgnat"))
    wan_ip = _s(ctx.wan.get("wan_ip")) or "?"
    gw = _s(ctx.wan.get("gateway")) or "?"
    if double is True:
        out.append(_finding(
            "double_nat", "medium", "internet",
            "Your internet goes through two routers (double NAT)",
            "NAT is how a router shares one internet address with all your devices. "
            "Here your provider's modem and your Deco both do it. "
            "That can cause trouble with online gaming, video calls and port forwarding.",
            [
                "Best fix: put your provider's modem/router into bridge mode or modem-only mode. "
                "Check its manual or ask your provider.",
                "Or switch the Deco to Access Point mode in %s. Then the Deco only makes the Wi-Fi, "
                "and your provider's router does the rest. Features like port forwarding and parental "
                "controls then live on your provider's router instead. The Decos restart when you switch."
                % _path("operation_mode"),
                "Pick one of these, not both, or nothing will hand out addresses.",
            ],
            "medium",
            "Deco's internet address is %s, a private address behind %s" % (wan_ip, gw),
            fix="put your provider's modem in bridge mode",
        ))
    if cgnat is True:
        out.append(_finding(
            "cgnat", "low", "internet",
            "Your provider shares one internet address between homes (CGNAT)",
            "CGNAT means your provider puts many homes behind one public address. "
            "Browsing, streaming and most games work fine. "
            "Hosting game servers or using port forwarding won't work.",
            ["If you need port forwarding, ask your provider for a public IP address."],
            "small",
            "Deco's internet address %s is in the shared CGNAT range (100.64.0.0/10)" % wan_ip,
            fix="ask your provider for a public IP address if you need port forwarding",
        ))
    if double is False and cgnat is not True:
        out.append(_finding(
            "no_double_nat", "good", "internet",
            "Your Deco connects straight to the internet",
            "Only one router shares your internet address. "
            "That's the best setup for gaming and video calls.",
            ["Nothing to fix here."],
            "small",
            "Deco's internet address: %s (public)" % wan_ip,
        ))
    return out


def rule_ipv6(ctx: _Ctx) -> list:
    v6 = _bool(ctx.wan.get("ipv6_enabled"))
    if v6 is False:
        return [_finding(
            "ipv6_off", "low", "settings",
            "IPv6 is turned off",
            "IPv6 is the newer kind of internet address. "
            "Some games, apps and providers work a little better with it. "
            "It only helps if your internet provider supports it.",
            [
                "Go to %s and turn it on." % _path("ipv6"),
                "Pick the type your provider uses. Dynamic IP is the default.",
                "If something stops working, turn it back off.",
            ],
            "small",
            "IPv6: off",
            fix="turn on IPv6 if your provider supports it",
        )]
    if v6 is True:
        return [_finding(
            "ipv6_on", "good", "settings",
            "IPv6 is on",
            "IPv6 is the newer kind of internet address, and your Deco is using it.",
            ["Nothing to fix here."],
            "small",
            "IPv6: on",
        )]
    return []


def _phy_gen(link: dict) -> int | None:
    gen = _num(link.get("wifi_gen"))
    if gen is not None and 1 <= gen <= 7:
        return int(gen)
    phy = (_s(link.get("phy")) or "").lower()
    table = {"802.11be": 7, "802.11ax": 6, "802.11ac": 5, "802.11n": 4,
             "802.11a": 3, "802.11g": 3, "802.11b": 1}
    return table.get(phy)


def rule_this_computer(ctx: _Ctx) -> list:
    out = []
    if ctx.link is None or ctx.link_type is None:
        return out
    lk = ctx.link
    if ctx.link_type == "ethernet" and ctx.eth_slow:
        rate = ctx.link_rate
        capped = ctx.down is not None and ctx.down >= 0.8 * rate
        how = [
            "Unplug the cable at both ends and push it back in until it clicks.",
            "Try another cable. Use one marked Cat5e or Cat6, because old or damaged cables often stop at 100 Mbps.",
            "Plug straight into a Deco, or try another port, instead of going through an old switch or wall socket.",
        ]
        if rate >= 1000 and ctx.plan_down and ctx.plan_down > rate:
            how.append("Your plan is faster than %s, so this computer also needs a faster network port "
                       "or a 2.5 Gbps USB adapter, plugged into a fast port on the Deco." % _mbps(rate))
        if ctx.plan_down:
            what_tail = "Your plan is %s, so this computer can't reach it over this cable." % _mbps(ctx.plan_down)
            evidence = "Cable link %s vs plan %s" % (_mbps(rate), _mbps(ctx.plan_down))
        else:
            what_tail = "Most computers and Decos can do at least 1000 Mbps, so something is holding it back."
            evidence = "Cable link %s" % _mbps(rate)
        if ctx.down is not None:
            evidence += ", download %s" % _mbps(ctx.down)
        out.append(_finding(
            "computer_ethernet_slow_link", "high" if capped else "medium", "this computer",
            "This computer's cable only connects at %s" % _mbps(rate),
            "The cable link speed is the fastest this computer can talk to the network. "
            "It's set by the cable and the ports at both ends. " + what_tail,
            how,
            "big" if capped else "medium",
            evidence,
            bottleneck="device",
            fix="check this computer's Ethernet cable and port",
        ))
        return out
    if ctx.link_type == "ethernet":
        out.append(_finding(
            "computer_on_ethernet", "good", "this computer",
            "This computer is plugged in with a cable",
            "A cable is the fastest and steadiest link. "
            "If it's plugged into the main Deco, your speed test shows what your internet can really do.",
            ["Nothing to fix here."],
            "small",
            "Connection type: Ethernet%s" % (" (%s)" % lk.get("interface") if _s(lk.get("interface")) else ""),
        ))
        return out

    rssi = ctx.link_rssi
    band = ctx.link_band
    band_txt = (" on %s" % _LINK_BAND_LABEL.get(band, band)) if band else ""
    if rssi is not None and rssi < -67:
        severity = "high" if rssi < -75 else "medium"
        # Same scale as the dashboard's signal guide: down to -67 good,
        # down to -75 okay, below that weak.
        out.append(_finding(
            "computer_weak_signal", severity, "this computer",
            "This computer's Wi-Fi signal is weak" if severity == "high"
            else "This computer's Wi-Fi signal could be stronger",
            "Wi-Fi signal is measured in dBm, and closer to 0 is stronger. "
            "-55 or better is great, down to -67 is good, down to -75 is okay, and below that is weak. "
            "A weaker signal means slower speed and more dropouts.",
            [
                "Move closer to a Deco, or move a Deco closer to where you use this computer.",
                "Keep the Deco up high and in the open.",
                "Thick walls, mirrors, fish tanks and big appliances block Wi-Fi.",
            ],
            "big",
            "Signal %s dBm%s%s (aim for -67 dBm or better)" % (
                _fmt(rssi), band_txt,
                # Windows without an Rssi line: wifi_link estimated dBm from the signal %.
                " (estimated from Windows' %s signal)" % _pct(_num(lk.get("signal_pct")))
                if lk.get("rssi_estimated") and _num(lk.get("signal_pct")) is not None
                else (" (estimated)" if lk.get("rssi_estimated") else "")),
            bottleneck="wifi signal",
            fix="move closer to a Deco, or move a Deco closer to this computer",
        ))
    snr = _num(lk.get("snr_db"))
    if snr is not None and snr < 20:
        noise = _num(lk.get("noise_dbm"))
        out.append(_finding(
            "computer_low_snr", "medium", "this computer",
            "There's a lot of Wi-Fi noise around this computer",
            "SNR compares your Wi-Fi signal with the background noise. "
            "Under 20 dB, the noise drowns out part of the signal. "
            "Wi-Fi then slows down to stay reliable.",
            [
                "Move closer to a Deco to make the signal stronger.",
                "On 2.4 GHz, microwaves, baby monitors and cordless phones can add noise, so keep away from them.",
            ],
            "medium",
            "SNR %s dB (signal %s dBm, noise %s dBm)" % (_fmt(snr), _fmt(rssi), _fmt(noise)),
            bottleneck="wifi signal",
            fix="get closer to a Deco and away from things that cause interference",
        ))
    if band == "2.4GHz":
        out.append(_finding(
            "computer_on_2g", "medium", "this computer",
            "This computer is on the slow 2.4 GHz band",
            "2.4 GHz reaches far but is slow and crowded. "
            "If this computer supports 5 GHz, it's usually on 2.4 GHz because it's far from a Deco.",
            [
                "Move closer to a Deco and turn Wi-Fi off and on again, so it picks a faster band.",
                "Make sure 5 GHz is on in %s." % _path("wifi_bands"),
            ],
            "medium",
            "Band 2.4 GHz%s" % ((", channel %s" % _fmt(lk.get("channel"))) if _num(lk.get("channel")) else ""),
            bottleneck="wifi signal",
            fix="get this computer onto 5 or 6 GHz by moving closer to a Deco",
        ))
    gen = _phy_gen(lk)
    deco_gen = _num(ctx.model.get("wifi_gen")) if ctx.model else None
    if gen is not None and gen <= 5 and (deco_gen is None or deco_gen > gen):
        deco_txt = ("Wi-Fi %d" % int(deco_gen)) if deco_gen else "newer Wi-Fi"
        out.append(_finding(
            "computer_old_wifi", "low", "this computer",
            "This computer has older Wi-Fi (Wi-Fi %d)" % gen,
            "Your Deco speaks %s, but this computer only speaks Wi-Fi %d. "
            "So here your device is the limit, not the Deco. "
            "That's fine for most things." % (deco_txt, gen),
            [
                "If you need more speed here, use an Ethernet cable.",
                "Or add a newer Wi-Fi 6E or Wi-Fi 7 adapter to this computer.",
            ],
            "small",
            "PHY %s (Wi-Fi %d)" % (_s(lk.get("phy")) or "?", gen),
            bottleneck="device",
            fix="use a cable or a newer Wi-Fi adapter on this computer",
        ))
    tx = ctx.link_tx
    if tx is not None and tx < 200:
        if ctx.plan_reached:
            # Slow link, but the speed test still reached the plan: not urgent.
            last = "At %s it's enough for your plan right now, but not for a faster one." % _mbps(tx)
            severity, impact = "low", "small"
        else:
            last = "At %s, fast speeds aren't possible here." % _mbps(tx)
            severity, impact = "medium", "medium"
        out.append(_finding(
            "computer_low_link_rate", severity, "this computer",
            "This computer's Wi-Fi link speed is low",
            "Link rate is the top speed your Wi-Fi connection allows right now. "
            "Real downloads are often only half to two-thirds of it. " + last,
            [
                "Move closer to a Deco, ideally in the same room.",
                "Make sure this computer is on 5 or 6 GHz, not 2.4 GHz.",
            ],
            impact,
            "Link rate %s%s" % (_mbps(tx), band_txt),
            bottleneck="wifi signal",
            fix="move closer to a Deco",
        ))
    elif ctx.plan_down and not ctx.plan_reached and ctx.link_rate is not None \
            and ctx.link_rate < 1.5 * ctx.plan_down:
        out.append(_finding(
            "computer_link_below_plan", "low", "this computer",
            "This computer's Wi-Fi link can't carry your whole plan",
            "Link rate is the top speed your Wi-Fi connection allows right now. "
            "Real downloads are often only half to two-thirds of it. "
            "Yours is too close to your plan's speed to reach it over Wi-Fi.",
            [
                "Move closer to a Deco or use 6 GHz if this computer supports it.",
                "For the full plan speed, use an Ethernet cable.",
            ],
            "small",
            "Link rate %s vs plan %s" % (_mbps(ctx.link_rate), _mbps(ctx.plan_down)),
            bottleneck="wifi signal",
            fix="move closer to a Deco or use a cable on this computer",
        ))
    if not out and rssi is not None and rssi >= -60 and band != "2.4GHz":
        out.append(_finding(
            "computer_signal_strong", "good", "this computer",
            "This computer has a strong Wi-Fi signal",
            "Your signal is strong and on a fast band, so distance to the Deco isn't the problem here.",
            ["Nothing to fix here."],
            "small",
            "Signal %s dBm%s%s" % (_fmt(rssi), band_txt,
                                   (", link rate %s" % _mbps(ctx.link_rate)) if ctx.link_rate else ""),
        ))
    return out


def rule_speed_vs_plan(ctx: _Ctx) -> list:
    out = []
    down, plan = ctx.down, ctx.plan_down
    if down is not None and plan:
        ratio = down / plan
        pct = _pct(100 * ratio)
        evidence = "Download %s vs plan %s (%s)" % (_mbps(down), _mbps(plan), pct)
        if ratio < 0.8:
            severity = "high" if ratio < 0.5 else "medium"
            wired = ctx.link_type == "ethernet"
            fast_link = (wired and not ctx.eth_slow) or (
                not wired and ctx.link_rate is not None and ctx.link_rate >= 2 * plan)
            gw_ok = (ctx.gw_median is not None and ctx.gw_median <= 10
                     and (ctx.gw_jitter is None or ctx.gw_jitter <= 10)
                     and (ctx.gw_loss is None or ctx.gw_loss <= 1))
            # Only blame the provider when nothing on this computer's Wi-Fi
            # link looks weak (the other rules would flag it otherwise).
            snr = _num(_d(ctx.link).get("snr_db"))
            wifi_ok = wired or ((ctx.link_rssi is None or ctx.link_rssi >= -67)
                                and (snr is None or snr >= 20)
                                and ctx.link_band != "2.4GHz")
            if fast_link and gw_ok and wifi_ok and not ctx.mesh_trouble:
                link_txt = "Ethernet" if wired else "link rate %s" % _mbps(ctx.link_rate)
                out.append(_finding(
                    "speed_below_plan_provider", severity, "internet",
                    "Your internet line is slower than your plan",
                    "Your connection to the Deco is fast and steady, but the speed test is still low. "
                    "So the slowdown is probably on your provider's side or in their modem.",
                    [
                        "To be sure, plug a computer into the main Deco with a cable and test again.",
                        "Restart your provider's modem by unplugging it for 30 seconds.",
                        "If it's still slow, contact your provider and show them these numbers.",
                    ],
                    "big",
                    "%s; %s; latency to your Deco %s ms" % (evidence, link_txt, _fmt(ctx.gw_median, 1)),
                    bottleneck="internet plan",
                    fix="test with a cable at the main Deco, then contact your provider",
                ))
            else:
                out.append(_finding(
                    "speed_below_plan", severity, "internet",
                    "You're getting %s of your plan's download speed" % pct,
                    "Your plan promises %s, but this test got %s. "
                    "Something between the internet and this computer is holding it back. "
                    "The other tips here point to the likely cause." % (_mbps(plan), _mbps(down)),
                    [
                        "Fix the top Wi-Fi and mesh items in this list first.",
                        "Then test again close to a Deco, or with a cable plugged into the main Deco.",
                        "Test at a few times of day, because evenings are often slower.",
                    ],
                    "big",
                    evidence,
                    fix="fix the Wi-Fi items in this list, then test again next to the main Deco",
                ))
        elif ratio >= 0.9:
            out.append(_finding(
                "plan_is_ceiling", "good", "internet",
                "You're getting the download speed you pay for",
                "This test reached %s of your plan. "
                "Your plan is now the ceiling, so only a faster plan can make it faster." % pct,
                ["Nothing to fix here."],
                "small",
                evidence,
            ))
        else:
            out.append(_finding(
                "speed_close_to_plan", "good", "internet",
                "You're getting close to your plan's speed",
                "This test reached %s of your plan. That's normal for a real-world test." % pct,
                ["Nothing to fix here. A cable test next to the main Deco may show a bit more."],
                "small",
                evidence,
            ))
    up, plan_up = ctx.up, ctx.plan_up
    if up is not None and plan_up and up / plan_up < 0.5:
        out.append(_finding(
            "upload_below_plan", "medium", "internet",
            "Your upload is well below your plan",
            "Upload is what you send, like video calls, streams and backups. "
            "Your plan promises %s up, but this test got %s." % (_mbps(plan_up), _mbps(up)),
            [
                "Test again close to a Deco, or with a cable at the main Deco.",
                "If it's still low on a cable, contact your provider.",
            ],
            "medium",
            "Upload %s vs plan %s (%s)" % (_mbps(up), _mbps(plan_up), _pct(100 * up / plan_up)),
            fix="test the upload with a cable at the main Deco",
        ))
    return out


def rule_bufferbloat(ctx: _Ctx) -> list:
    sp = ctx.speed or {}
    grade = _s(sp.get("bufferbloat_grade"))
    if not grade:
        return []
    grade = grade.upper()
    idle = _num(sp.get("idle_latency_ms"))
    loaded = [v for v in (_num(sp.get("loaded_latency_down_ms")), _num(sp.get("loaded_latency_up_ms")))
              if v is not None]
    extra = _num(sp.get("bufferbloat_ms"))
    evidence = "Grade %s: idle %s ms, busy %s ms (+%s ms)" % (
        grade, _fmt(idle), _fmt(max(loaded) if loaded else None), _fmt(extra))
    if grade in ("C", "D", "F"):
        severity = "medium" if grade == "C" else "high"
        parts = []
        if ctx.down:
            parts.append("%s down" % _mbps(ctx.down * 0.9))
        if ctx.up:
            parts.append("%s up" % _mbps(ctx.up * 0.9))
        if parts:
            target = "about %s (90%% of your measured speed)" % " and ".join(parts)
        else:
            target = "about 90% of your measured speed"
        # TP-Link FAQ 1601: Deco QoS asks for the Total Bandwidth, then puts
        # chosen activities or devices first. It isn't promised to remove lag.
        return [_finding(
            "bufferbloat", severity, "internet",
            "Your connection lags when it's busy (bufferbloat grade %s)" % grade,
            "Bufferbloat is extra lag that shows up when someone is downloading or uploading. "
            "Games stutter and video calls freeze while the line is busy. "
            "QoS (Quality of Service) can help by putting games, calls or chosen devices first.",
            [
                "Go to %s and turn QoS on." % _path("qos"),
                "When it asks for your Total Bandwidth, enter %s. "
                "If it asks for one number only, use the download one." % target,
                "Pick what goes first: Gaming or Video Conferencing, or the devices you care about most.",
                "Run the speed test again and check that the grade improves.",
            ],
            "big",
            evidence,
            bottleneck="bufferbloat",
            fix="turn on QoS in the Deco app at about 90% of your measured speed",
        )]
    if grade in ("A+", "A", "B"):
        return [_finding(
            "bufferbloat_ok", "good", "internet",
            "No lag spikes when your line is busy",
            "Bufferbloat is extra lag when the line is busy. Yours stays low, which is great for games and calls.",
            ["Nothing to fix here."],
            "small",
            evidence,
        )]
    return []


def rule_latency(ctx: _Ctx) -> list:
    out = []
    med, jit, loss = ctx.gw_median, ctx.gw_jitter, ctx.gw_loss
    if ctx.gateway is not None and (med is not None or loss is not None):
        bad_med = med is not None and med > 10
        bad_jit = jit is not None and jit > 10
        bad_loss = loss is not None and loss > 1
        evidence = "To your Deco: median %s ms, jitter %s ms, loss %s" % (
            _fmt(med, 1), _fmt(jit, 1), _pct(loss))
        if bad_med or bad_jit or bad_loss:
            high = (med is not None and med > 30) or (jit is not None and jit > 30) or \
                (loss is not None and loss > 5)
            intro = ("We timed how long this computer takes to reach your Deco. "
                     "On a good home network that's just a few milliseconds and very even. ")
            if ctx.link_type == "ethernet":
                # On a cable, Wi-Fi isn't the cause: blame the cable, a switch,
                # a busy Deco, or a satellite's own backhaul.
                out.append(_finding(
                    "local_connection_unsteady", "high" if high else "medium", "this computer",
                    "The link from this computer to your Deco is laggy",
                    intro + "You're on a cable, so slow or jumpy times point to the cable, "
                    "a switch in between, or a busy Deco.",
                    [
                        "Try a different network cable and a different port on the Deco.",
                        "If there's a switch in between, plug straight into the Deco to test.",
                        "If you're plugged into a satellite Deco, check its link in %s." % _path("network_map"),
                        "Restart the Deco by unplugging it for 10 seconds.",
                    ],
                    "medium",
                    evidence + "; this computer is on Ethernet",
                    fix="try another cable and port on the Deco",
                ))
            else:
                out.append(_finding(
                    "local_connection_unsteady", "high" if high else "medium", "wifi",
                    "The link from this computer to your Deco is laggy",
                    intro + "Slow, jumpy times or lost data point to Wi-Fi trouble, not your internet.",
                    [
                        "Move closer to a Deco and use 5 or 6 GHz.",
                        "Pause big downloads on this computer and test again.",
                        "If you're near a satellite Deco, check its link in %s." % _path("network_map"),
                    ],
                    "medium",
                    evidence,
                    bottleneck="wifi signal",
                    fix="move closer to a Deco and use 5 or 6 GHz",
                ))
        elif med is not None:
            out.append(_finding(
                "gateway_latency_ok", "good", "wifi",
                "Your link to the Deco is quick and steady",
                "This computer reaches your Deco fast, with no lost data.",
                ["Nothing to fix here."],
                "small",
                evidence,
            ))
    losses = [_num(t.get("loss_pct")) for t in ctx.internet_targets]
    losses = [v for v in losses if v is not None]
    if losses:
        # The smallest loss across targets: if even the best target loses
        # data, the problem is on your side of the internet, not one server.
        if min(losses) > 1:
            local = loss is not None and loss > 1
            wired = ctx.link_type == "ethernet"
            how = []
            if local and wired:
                how.append("This computer also loses data to your Deco, so check its cable, port and any switch first.")
            elif local:
                how.append("This computer also loses data to your Deco, so fix the Wi-Fi first.")
            how.extend([
                "Restart your provider's modem and the main Deco.",
                "Check the cable between the modem and the main Deco.",
                "If it keeps happening, tell your provider. It's probably on their side.",
            ])
            out.append(_finding(
                "internet_packet_loss", "high", "internet",
                "Some data is getting lost on the way to the internet",
                "Packet loss means bits of data never arrive and have to be sent again. "
                "Over 1% makes games and video calls glitch.",
                how,
                "big",
                "; ".join("%s: loss %s" % (_s(t.get("name")) or _s(t.get("host")) or "?", _pct(_num(t.get("loss_pct"))))
                          for t in ctx.internet_targets if _num(t.get("loss_pct")) is not None),
                bottleneck=(None if wired else "wifi signal") if local else "internet plan",
                fix=("check this computer's cable and port to the Deco first" if local and wired else
                     "fix this computer's Wi-Fi link first (move closer to a Deco)" if local else
                     "restart your modem and contact your provider if the loss continues"),
            ))
    return out


def _is_local_ip(text) -> bool | None:
    """True for home-network/loopback addresses, False for public ones, None if unsure."""
    try:
        ip = ipaddress.ip_address(str(text).split("%")[0].strip())
    except ValueError:
        return None
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


# Public DNS servers we'd suggest anyway. If one is already in use, swapping
# servers won't help much.
_FAST_DNS = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112")


def rule_dns(ctx: _Ctx) -> list:
    med = ctx.dns_median
    if med is None:
        return []
    if med > 80:
        resolvers = [r.strip() for r in _l(_d(ctx.dns).get("resolvers")) if isinstance(r, str) and r.strip()]
        # This computer asks public DNS servers directly (not the Deco), so
        # changing the Deco's DNS would not help it.
        own_dns = bool(resolvers) and all(_is_local_ip(r) is False for r in resolvers)
        deco_dns = [d.strip() for d in _l(ctx.wan.get("dns")) if isinstance(d, str) and d.strip()]
        in_use = resolvers if own_dns else deco_dns
        already_fast = [d for d in in_use if d in _FAST_DNS]
        if already_fast:
            who = "This computer" if own_dns else "Your Deco"
            how = [
                "%s already uses %s, which is usually fast. So the line itself is probably busy or slow."
                % (who, _join(already_fast[:2])),
                "Pause big downloads and run the DNS test again.",
                "If you use a VPN or a security app on this computer, test once with it off.",
            ]
            fix = "pause big downloads and run the DNS test again"
        elif own_dns:
            how = [
                "This computer asks %s for DNS directly, not your Deco. "
                "So change the DNS in this computer's network settings to 1.1.1.1 and 8.8.8.8."
                % _join(resolvers[:2]),
                "Or switch this computer back to automatic DNS, then set the Deco's DNS in %s." % _path("dns"),
                "Run the DNS test again to check it's faster.",
            ]
            fix = "switch this computer's DNS to 1.1.1.1 and 8.8.8.8"
        else:
            how = [
                "Go to %s and enter 1.1.1.1 (Cloudflare) and 8.8.8.8 (Google)." % _path("dns"),
                "If your app won't let you, use %s instead." % _path("dns_dhcp"),
                "Run the DNS test again to check it's faster.",
            ]
            fix = "switch the Deco's DNS to 1.1.1.1 and 8.8.8.8"
        evidence = "DNS median %s ms" % _fmt(med)
        if resolvers:
            evidence += " (asking %s)" % ", ".join(resolvers[:3])
        if not own_dns and deco_dns:
            evidence += "; Deco's DNS: %s" % ", ".join(deco_dns[:3])
        return [_finding(
            "dns_slow", "medium", "internet",
            "Website lookups are slow (DNS)",
            "DNS turns website names into addresses, like a phone book. "
            "Every new site waits for it. "
            "Yours takes %s ms, and a fast one often answers in under 30 ms." % _fmt(med),
            how,
            "medium",
            evidence,
            bottleneck="dns",
            fix=fix,
        )]
    return [_finding(
        "dns_ok", "good", "internet",
        "Website lookups are fast",
        "DNS turns website names into addresses. Yours answers quickly.",
        ["Nothing to fix here."],
        "small",
        "DNS median %s ms" % _fmt(med),
    )]


def rule_rooms(ctx: _Ctx) -> list:
    rooms = [r for r in ctx.rooms if _num(r.get("down_mbps")) is not None or _num(r.get("rssi_dbm")) is not None]
    if len(rooms) < 2:
        return []
    downs = [_num(r.get("down_mbps")) for r in rooms if _num(r.get("down_mbps")) is not None]
    best = max(downs) if downs else None
    best_room = None
    if best is not None:
        for r in rooms:
            if _num(r.get("down_mbps")) == best:
                best_room = r
                break
    weak = []
    for r in rooms:
        d = _num(r.get("down_mbps"))
        rssi = _num(r.get("rssi_dbm"))
        slow = best is not None and best > 0 and d is not None and d < 0.5 * best
        faint = rssi is not None and rssi < -70
        if slow or faint:
            weak.append(r)

    def room_text(r):
        bits = [_mbps(r.get("down_mbps")) if _num(r.get("down_mbps")) is not None else None,
                ("%s dBm" % _fmt(r.get("rssi_dbm"))) if _num(r.get("rssi_dbm")) is not None else None]
        text = "%s: %s" % (_s(r.get("room")), ", ".join(b for b in bits if b))
        node = _s(r.get("node_name"))
        if node:
            text += " (via %s)" % _q(node)
        return text

    if weak:
        weak.sort(key=lambda r: (_num(r.get("down_mbps")) if _num(r.get("down_mbps")) is not None else 1e9))
        names = [_s(r.get("room")) for r in weak]
        first = names[0]
        best_txt = ""
        if best_room is not None and best_room not in weak:
            best_txt = "; best: %s" % room_text(best_room)
        return [_finding(
            "weak_room", "medium", "wifi",
            "Wi-Fi is weak in the %s" % _join(names),
            "Your room tests show the %s %s much slower or %s a weaker signal than your best room. "
            "That usually means no Deco is close enough."
            % (_join(names), _verb(names, "is", "are"), _verb(names, "has", "have")),
            [
                "Move a satellite Deco to about halfway between the main Deco and the %s." % first,
                "Keep it in the open and off the floor, then run the room test again.",
                "If you can, connect that Deco with an Ethernet cable.",
            ],
            "medium",
            "; ".join(room_text(r) for r in weak) + best_txt,
            bottleneck="wifi signal",
            fix="move a satellite about halfway between the main Deco and the %s" % first,
        )]
    return [_finding(
        "rooms_even", "good", "wifi",
        "Wi-Fi is even across the rooms you tested",
        "Every room you tested gets at least half the speed of your best room, with a decent signal.",
        ["Nothing to fix here."],
        "small",
        "; ".join(room_text(r) for r in rooms),
    )]


def rule_missing_data(ctx: _Ctx) -> list:
    out = []
    if not ctx.cov_deco:
        evidence = "Not logged in to the Deco yet"
        if ctx.deco_error:
            evidence += " (last error: %s)" % ctx.deco_error
        out.append(_finding(
            "need_deco_login", "low", "this computer",
            "Log in to your Deco to check the mesh",
            "Without logging in we can't see your Decos, their links or their settings. "
            "Most fixes come from that data.",
            [
                "Enter your Deco owner password (the TP-Link ID password) and log in.",
                "This logs the Deco app on your phone out, which is normal.",
            ],
            "small",
            evidence,
            fix="log in to your Deco",
            scored=False,
        ))
    missing = []
    if not ctx.cov_link:
        missing.append("Wi-Fi link")
    if not ctx.cov_latency:
        missing.append("latency")
    if not ctx.cov_dns:
        missing.append("DNS")
    if missing:
        out.append(_finding(
            "need_quick_check", "low", "this computer",
            "Run the quick check",
            "The quick check measures this computer's Wi-Fi, its lag to the Deco and your DNS speed. "
            "It takes under a minute.",
            ["Press the quick check button on this page."],
            "small",
            "Not measured yet: %s" % ", ".join(missing),
            fix="run the quick check",
            scored=False,
        ))
    if not ctx.cov_speed:
        out.append(_finding(
            "need_speed_test", "low", "this computer",
            "Run a speed test",
            "A speed test shows how fast your internet really is from here. "
            "It also checks for lag when the line is busy.",
            ["Press the speed test button. It takes about 20 seconds."],
            "small",
            "No speed test yet",
            fix="run a speed test",
            scored=False,
        ))
    if ctx.plan_down is None:
        out.append(_finding(
            "need_plan_speed", "low", "this computer",
            "Tell us your internet plan's speed",
            "With your plan's speed we can tell if you get what you pay for.",
            ["Enter the download and upload speed from your plan in the settings box."],
            "small",
            "Plan speed not set",
            fix="enter your internet plan's speed",
            scored=False,
        ))
    if len(ctx.rooms) < 2:
        out.append(_finding(
            "need_room_tests", "low", "this computer",
            "Run room tests in a few rooms",
            "A room test runs the same check from different spots. "
            "Comparing them shows weak areas and Decos in the wrong place.",
            ["Take this computer to 2 or 3 rooms, type the room name and press Room test in each."],
            "small",
            "Rooms tested: %d" % len(ctx.rooms),
            fix="run room tests in a few rooms",
            scored=False,
        ))
    return out


RULES = [
    rule_units_offline,
    rule_backhaul_signal,
    rule_ethernet_backhaul,
    rule_daisy_chain,
    rule_backhaul_link_rate,
    rule_firmware,
    rule_main_busy,
    rule_clients_on_2g,
    rule_client_balance,
    rule_bands_disabled,
    rule_channel_width,
    rule_mlo,
    rule_network_names,
    rule_nat,
    rule_ipv6,
    rule_this_computer,
    rule_speed_vs_plan,
    rule_bufferbloat,
    rule_latency,
    rule_dns,
    rule_rooms,
    rule_missing_data,
]


# ---------------------------------------------------------------------------
# Checklist ("optimal setup")
# ---------------------------------------------------------------------------

def _item(cid, title, status, detail, how) -> dict:
    return {"id": cid, "title": title, "status": status, "detail": detail, "how": how}


def _unread(ctx) -> str:
    """Detail text when a Deco value is missing: log in, or the Deco didn't say."""
    if ctx.cov_deco:
        return "Your Deco didn't share this. Check it in the Deco app."
    return "Log in to your Deco to check this."


def _check_ethernet_backhaul(ctx):
    title = "Ethernet backhaul for every satellite"
    how = ("Run a cable from the main Deco (or a switch plugged into it) to each satellite. "
           "The Deco switches to the cable by itself.")
    if not ctx.cov_deco or not ctx.nodes:
        return _item("ethernet_backhaul", title, "unknown", _unread(ctx), how)
    if not ctx.satellites:
        return _item("ethernet_backhaul", title, "pass", "You have one Deco, so there's nothing to wire.", how)
    wireless = [n for n in ctx.satellites if n.get("backhaul") == "wireless"]
    wired = [n for n in ctx.satellites if n.get("backhaul") == "wired"]
    if wireless:
        return _item("ethernet_backhaul", title, "fail",
                     "On Wi-Fi: %s." % _join([_q(_node_name(n)) for n in wireless]), how)
    if len(wired) == len(ctx.satellites):
        return _item("ethernet_backhaul", title, "pass", "Every satellite uses a cable.", how)
    return _item("ethernet_backhaul", title, "unknown", "The Deco didn't say how some satellites connect.", how)


def _check_signal(ctx):
    title = "Strong signal between Decos"
    how = "Place each satellite about halfway between the main Deco and the area that needs Wi-Fi, in the open."
    if not ctx.cov_deco or not ctx.nodes:
        return _item("strong_satellite_signal", title, "unknown", _unread(ctx), how)
    if not ctx.satellites:
        return _item("strong_satellite_signal", title, "pass", "You have one Deco, so there's no link to check.", how)
    levels = []
    weak = []
    for n in ctx.satellites:
        if n.get("backhaul") == "wired":
            levels.append("ok")
            continue
        st = ctx.sat_status.get(id(n)) or {}
        levels.append(st.get("level"))
        if st.get("level") in ("high", "medium"):
            weak.append(_q(_node_name(n)))
    if weak:
        return _item("strong_satellite_signal", title, "fail", "Weak link: %s." % _join(weak), how)
    if levels and all(lv == "ok" for lv in levels):
        return _item("strong_satellite_signal", title, "pass", "Every satellite has a strong link or a cable.", how)
    return _item("strong_satellite_signal", title, "unknown", "The Deco didn't report signal for every satellite.", how)


def _check_six_ghz(ctx):
    title = "6 GHz Wi-Fi turned on"
    how = "Turn on the 6 GHz network in %s." % _path("six_ghz")
    has = ctx.has_band("band6")
    enabled = ctx.band_cfg("band6").get("enabled")
    if has is False:
        return _item("six_ghz_on", title, "pass", "Your Deco model has no 6 GHz band, so there's nothing to do.", how)
    if enabled is True:
        return _item("six_ghz_on", title, "pass", "6 GHz is on.", how)
    if enabled is False:
        return _item("six_ghz_on", title, "fail", "6 GHz is off.", how)
    return _item("six_ghz_on", title, "unknown", _unread(ctx), how)


def _check_mlo(ctx):
    title = "MLO network on (for Wi-Fi 7 devices)"
    how = "Turn it on in %s, then join it with your Wi-Fi 7 devices." % _path("mlo")
    if ctx.model and ctx.model.get("supports_mlo") is False:
        return _item("mlo_on", title, "pass", "Your Deco model doesn't have MLO, so there's nothing to do.", how)
    mlo = _bool(ctx.wifi.get("mlo_enabled"))
    if mlo is True:
        return _item("mlo_on", title, "pass", "MLO is on.", how)
    if mlo is False:
        return _item("mlo_on", title, "fail", "MLO is off.", how)
    return _item("mlo_on", title, "unknown", "We couldn't read this setting. Check it in the app.", how)


def _check_one_name(ctx):
    title = "One network name for all bands"
    how = "In %s, give every band the same name and password. The MLO network keeps its own name." % _path("wifi_settings")
    same = _bool(ctx.wifi.get("same_ssid_all_bands"))
    if same is True:
        return _item("one_network_name", title, "pass", "All bands share one name.", how)
    if same is False:
        return _item("one_network_name", title, "fail", "Your bands use different names.", how)
    return _item("one_network_name", title, "unknown", _unread(ctx), how)


def _check_hidden(ctx):
    title = "Network name not hidden"
    how = "Switch this off: %s." % _path("hide_network")
    flags = [ctx.band_cfg(b).get("hidden") for b in ("band2_4", "band5", "band6") if ctx.band_cfg(b)]
    if any(f is True for f in flags):
        return _item("no_hidden_network", title, "fail", "Your network name is hidden.", how)
    # The Deco app has one "Hide this network" switch, and firmware often only
    # reports it on one band, so one False (and no True) is enough.
    if any(f is False for f in flags):
        return _item("no_hidden_network", title, "pass", "Your network name is visible.", how)
    return _item("no_hidden_network", title, "unknown", _unread(ctx), how)


def _check_fast_roaming(ctx):
    return _item("fast_roaming", "Fast Roaming on", "manual",
                 "We can't read this setting. It helps phones switch Decos faster as you walk around.",
                 "Turn it on in %s. %s" % (_path("fast_roaming"), FAST_ROAMING_CAVEAT))


def _check_beamforming(ctx):
    return _item("beamforming", "Beamforming on", "manual",
                 "We can't read this setting. Beamforming aims the signal at your devices.",
                 "Turn it on in %s. If you can't find it, your model keeps it on all the time."
                 % _path("beamforming"))


def _check_iot(ctx):
    title = "IoT network for smart-home gadgets"
    how = "Turn it on in %s and connect smart plugs, bulbs and cameras to it (if your app shows it)." % _path("iot_network")
    iot = _bool(ctx.wifi.get("iot_enabled"))
    if iot is True:
        return _item("iot_network", title, "pass", "Your IoT network is on.", how)
    on_2g = len([c for c in ctx.clients if c.get("band") == "band2_4" and c.get("online") is not False])
    if iot is False and on_2g >= 3:
        return _item("iot_network", title, "fail",
                     "It's off, and %d devices are on 2.4 GHz. Smart gadgets would be happier on their own network." % on_2g,
                     how)
    if iot is False:
        return _item("iot_network", title, "manual",
                     "It's off. You only need it if you have smart-home gadgets.", how)
    return _item("iot_network", title, "unknown", "We couldn't read this setting. Check it in the app.", how)


def _check_qos(ctx):
    title = "QoS on if your line lags when busy"
    how = ("Turn on QoS in %s, set the Total Bandwidth to about 90%% of your measured speed, "
           "and put games or calls first." % _path("qos"))
    grade = (_s((ctx.speed or {}).get("bufferbloat_grade")) or "").upper()
    if grade in ("C", "D", "F"):
        return _item("qos_for_bufferbloat", title, "fail",
                     "Bufferbloat grade %s, so QoS should help." % grade, how)
    if grade in ("A+", "A", "B"):
        return _item("qos_for_bufferbloat", title, "pass",
                     "Bufferbloat grade %s, so QoS is optional." % grade, how)
    return _item("qos_for_bufferbloat", title, "unknown", "Run a speed test to check this.", how)


def _check_firmware(ctx):
    title = "Firmware up to date (and the same on every Deco)"
    how = "Check %s and install any update." % _path("firmware")
    mixed = False
    try:
        mixed = bool(rule_firmware(ctx))
    except Exception:
        mixed = False
    if mixed:
        return _item("firmware", title, "fail", "Your Decos run different firmware versions.", how)
    versions = sorted(set(" ".join(_s(n.get("fw_version")).split()) for n in ctx.nodes if _s(n.get("fw_version"))))
    if versions:
        detail = "Your Decos match (%s). We can't see if a newer version exists." % "; ".join(versions)
    else:
        detail = "We can't see if a newer version exists."
    return _item("firmware", title, "manual", detail, how)


def _check_double_nat(ctx):
    title = "No double NAT"
    how = "Put your provider's modem in bridge mode, or switch the Deco to Access Point mode in %s." % _path("operation_mode")
    double = _bool(ctx.wan.get("double_nat"))
    if double is True:
        return _item("no_double_nat", title, "fail", "Your Deco sits behind another router.", how)
    if double is False:
        return _item("no_double_nat", title, "pass", "Only one router shares your internet address.", how)
    return _item("no_double_nat", title, "unknown", _unread(ctx), how)


def _check_ipv6(ctx):
    title = "IPv6 on (if your provider supports it)"
    how = "Turn it on in %s." % _path("ipv6")
    v6 = _bool(ctx.wan.get("ipv6_enabled"))
    if v6 is True:
        return _item("ipv6", title, "pass", "IPv6 is on.", how)
    if v6 is False:
        return _item("ipv6", title, "fail", "IPv6 is off. Turn it on if your provider supports it.", how)
    return _item("ipv6", title, "unknown", "We couldn't read this setting. Check it in the app.", how)


def _check_dns(ctx):
    title = "Fast DNS"
    how = "If it's slow, set DNS to 1.1.1.1 and 8.8.8.8 in %s." % _path("dns")
    med = ctx.dns_median
    if med is None:
        return _item("dns_fast", title, "unknown", "Run the quick check to measure this.", how)
    if med > 80:
        return _item("dns_fast", title, "fail", "DNS takes %s ms." % _fmt(med), how)
    return _item("dns_fast", title, "pass", "DNS takes %s ms." % _fmt(med), how)


def _check_multigig(ctx):
    title = "2.5 Gbps port and Cat6 cable for plans over 1 Gbps"
    how = ("Plug your modem into a 2.5 Gbps (or faster) port on the main Deco with a Cat6 cable. "
           "Use the same kind of port and cable for wired satellites.")
    plans = [p for p in (ctx.plan_down, ctx.plan_up) if p]
    if not plans:
        return _item("multi_gig_port", title, "unknown", "Enter your plan's speed to check this.", how)
    if max(plans) <= 1000:
        return _item("multi_gig_port", title, "pass",
                     "Your plan fits in a normal 1 Gbps port, so any port works.", how)
    m = ctx.model
    if m and _num(m.get("max_port_gbps")) is not None and _num(m.get("max_port_gbps")) < 2.5:
        return _item("multi_gig_port", title, "fail",
                     "Your plan is over 1 Gbps, but the %s only has %s." % (m.get("name"), m.get("ports")), how)
    if m:
        detail = "Your plan is over 1 Gbps. Your %s has %s, so check the cable goes into one of those." % (
            m.get("name"), m.get("ports"))
    else:
        detail = "Your plan is over 1 Gbps. Check your modem uses a 2.5 Gbps port on the main Deco."
    return _item("multi_gig_port", title, "manual", detail, how)


def _check_placement(ctx):
    return _item("main_deco_placement", "Main Deco central, up high and in the open", "manual",
                 "We can't see where your Decos are. Placement makes a big difference.",
                 "Put the main Deco near the middle of your home, on a shelf or desk, "
                 "away from walls, metal, mirrors and TVs.")


CHECKS = [
    _check_ethernet_backhaul,
    _check_signal,
    _check_six_ghz,
    _check_mlo,
    _check_one_name,
    _check_hidden,
    _check_fast_roaming,
    _check_beamforming,
    _check_iot,
    _check_qos,
    _check_firmware,
    _check_double_nat,
    _check_ipv6,
    _check_dns,
    _check_multigig,
    _check_placement,
]


# ---------------------------------------------------------------------------
# Scoring, bottleneck and headline
# ---------------------------------------------------------------------------

def _sort_key(f: dict):
    return (SEVERITY_ORDER.get(f.get("severity"), 9), IMPACT_ORDER.get(f.get("impact"), 9))


def _weight(f: dict) -> int:
    return _SEV_WEIGHT.get(f.get("severity"), 0) * _IMPACT_WEIGHT.get(f.get("impact"), 1)


def score_findings(findings: list) -> int:
    score = SCORE_MAX
    for f in findings:
        if f.get("_scored", True) is False:
            continue
        score -= PENALTY.get(f.get("severity"), 0)
    return max(SCORE_MIN, min(SCORE_MAX, score))


def grade_for(score) -> str | None:
    if score is None:
        return None
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def _best(findings: list):
    """Heaviest finding; ties go to the one listed first (rule order)."""
    best = None
    for f in findings:
        if best is None or _weight(f) > _weight(best):
            best = f
    return best


def _pick_bottleneck(ctx: _Ctx, findings: list, has_data: bool):
    """Return (bottleneck, top_finding_or_None)."""
    if not has_data:
        return "not enough data", None
    ids = set(f["id"] for f in findings)
    tagged = [f for f in findings if f.get("severity") != "good" and f.get("_bn") in _BN_PRIORITY]
    strong = [f for f in tagged if f.get("severity") in ("critical", "high", "medium")]
    if strong:
        # A speed test that fills this computer's slow cable link is capped by that
        # cable, whatever else is wrong, so the cable is the limit we measured.
        capped = [f for f in strong if f["id"] == "computer_ethernet_slow_link" and f["severity"] == "high"]
        top = capped[0] if capped else _best(strong)
        return top["_bn"], top
    if "plan_is_ceiling" in ids or "speed_close_to_plan" in ids:
        return "internet plan", None
    if "speed_below_plan" in ids:
        if tagged:
            top = _best(tagged)
            return top["_bn"], top
        if not ctx.cov_link or not ctx.cov_latency:
            return "not enough data", None
        if ctx.link_type == "ethernet":
            return "internet plan", None
        return "wifi signal", None
    if not ctx.cov_speed:
        return "not enough data", None
    if tagged:
        top = _best(tagged)
        return top["_bn"], top
    return "none found", None


def _headline(ctx: _Ctx, bottleneck: str, top, findings: list) -> str:
    problems = [f for f in findings if f.get("severity") != "good" and f.get("_scored", True)]
    if top is not None and top.get("severity") == "critical":
        return "Something is down right now, so first %s." % (top.get("_fix") or "check your Decos")
    if bottleneck == "not enough data":
        if not ctx.cov_deco and not ctx.cov_speed:
            step = "log in to your Deco and run a speed test"
        elif not ctx.cov_deco:
            step = "log in to your Deco"
        elif not ctx.cov_speed:
            step = "run a speed test"
        else:
            step = "run the quick check and a room test"
        return "There isn't enough data yet to find what slows you down, so the next step is to %s." % step
    if bottleneck == "none found":
        if problems:
            first = sorted(problems, key=_sort_key)[0]
            fix = first.get("_fix") or "work through the tips below"
            if first.get("severity") in ("critical", "high", "medium"):
                # Don't say "nothing big" while a medium-or-worse problem is listed.
                return "We didn't find one clear speed limit, but the top tip is to %s." % fix
            return "Nothing big is slowing you down, and the best small win is to %s." % fix
        return "Your network looks great and nothing is holding it back right now."
    if bottleneck == "internet plan" and top is None:
        ids = set(f.get("id") for f in findings)
        if "plan_is_ceiling" in ids or "speed_close_to_plan" in ids:
            if "upload_below_plan" in ids:
                return ("Your download already reaches your plan, but your upload is well below it, "
                        "so the number-one fix is to test the upload with a cable at the main Deco.")
            return ("Your home network keeps up with your internet plan, so the plan itself is the ceiling "
                    "and only a faster plan would make it faster.")
        return ("Your home network looks fine, so your internet line is the likely limit, and the number-one fix is "
                "to test with a cable at the main Deco and then talk to your provider.")
    if top is None:
        if bottleneck == "wifi signal":
            return ("Your Wi-Fi signal is the likely limit, so the number-one fix is to "
                    "move closer to a Deco or move a Deco closer to you.")
        return "Your biggest slowdown is %s, so start with the top tip below." % _BN_LABEL.get(bottleneck, bottleneck)
    return "Your biggest slowdown is %s, so the number-one fix is to %s." % (
        _BN_LABEL.get(bottleneck, bottleneck), top.get("_fix") or "follow the top tip below")


def _public(f: dict) -> dict:
    return {k: v for k, v in f.items() if not k.startswith("_")}


def _fallback(error: str) -> dict:
    return {
        "score": None,
        "grade": None,
        "headline": "Something went wrong while checking your network. Try running the check again.",
        "bottleneck": "not enough data",
        "findings": [],
        "checklist": [],
        "data_coverage": {"deco": False, "link": False, "latency": False, "speed": False, "dns": False, "rooms": 0},
        "rule_errors": [error],
    }


def analyze(snapshot: dict) -> dict:
    """Turn a Snapshot into an Analysis. Never raises."""
    try:
        ctx = _Ctx(snapshot)
    except Exception as exc:  # pragma: no cover - _Ctx is defensive already
        return _fallback("context: %s" % exc.__class__.__name__)

    findings = []
    errors = []
    for rule in RULES:
        try:
            result = rule(ctx)
        except Exception as exc:
            errors.append("%s: %s" % (getattr(rule, "__name__", "rule"), exc.__class__.__name__))
            continue
        for f in result or []:
            if isinstance(f, dict) and f.get("id"):
                findings.append(f)

    # Stable sort keeps rule order inside the same severity and impact.
    findings.sort(key=_sort_key)

    checklist = []
    for check in CHECKS:
        try:
            item = check(ctx)
        except Exception as exc:
            errors.append("%s: %s" % (getattr(check, "__name__", "check"), exc.__class__.__name__))
            continue
        if isinstance(item, dict):
            checklist.append(item)

    has_data = ctx.cov_deco or ctx.cov_link or ctx.cov_latency or ctx.cov_speed or ctx.cov_dns
    score = score_findings(findings) if has_data else None

    try:
        bottleneck, top = _pick_bottleneck(ctx, findings, has_data)
    except Exception as exc:
        errors.append("bottleneck: %s" % exc.__class__.__name__)
        bottleneck, top = ("not enough data" if not has_data else "none found"), None
    try:
        headline = _headline(ctx, bottleneck, top, findings)
    except Exception as exc:
        errors.append("headline: %s" % exc.__class__.__name__)
        headline = "Here's what we found on your network."

    return {
        "score": score,
        "grade": grade_for(score),
        "headline": headline,
        "bottleneck": bottleneck,
        "findings": [_public(f) for f in findings],
        "checklist": checklist,
        "data_coverage": {
            "deco": bool(ctx.cov_deco),
            "link": bool(ctx.cov_link),
            "latency": bool(ctx.cov_latency),
            "speed": bool(ctx.cov_speed),
            "dns": bool(ctx.cov_dns),
            "rooms": len(ctx.rooms),
        },
        # optional extra: names of rules that crashed (empty when all is well)
        "rule_errors": errors,
    }
