/* Deco Wi-Fi Dashboard front end.
 *
 * Plain JavaScript, no libraries, no external files.
 * Safety rule: device names and everything else come from the network and
 * could contain HTML, so the page is built with DOM nodes and textContent
 * only. innerHTML is never used.
 */
(function () {
  "use strict";

  var NOT_YET = "not measured yet";
  var SVG_NS = "http://www.w3.org/2000/svg";
  var TOKEN = readToken();

  var state = null;
  var lastKey = "";
  var pollTimer = null;
  var messageTimer = null;
  var formsFilled = false;
  var loginError = "";
  var deviceFilter = "";
  var openFindings = dict();
  var busy = {};

  var JOB_ORDER = ["deco", "link", "latency", "dns", "speed", "room"];
  var JOB_LABELS = {
    deco: "Deco", link: "This computer", latency: "Ping", dns: "DNS",
    speed: "Speed test", room: "Room test"
  };
  var BAND_LABELS = {
    band2_4: "2.4 GHz", band5: "5 GHz", band5_2: "5 GHz (second)", band6: "6 GHz",
    wired: "Wired", unknown: "Unknown"
  };
  var DEVICE_BANDS = ["band6", "band5", "band2_4", "wired", "unknown"];
  var SEV_LABELS = { critical: "Critical", high: "High", medium: "Medium", low: "Low", good: "Good" };
  var IMPACT_LABELS = { big: "Big impact", medium: "Medium impact", small: "Small impact" };
  var BOTTLENECKS = {
    "internet plan": "Main limit: your internet plan",
    "wifi signal": "Main limit: Wi-Fi signal",
    "mesh backhaul": "Main limit: the link between your Decos",
    "bufferbloat": "Main limit: lag when the line is busy",
    "device": "Main limit: this device",
    "dns": "Main limit: slow DNS",
    "none found": "No big bottleneck found",
    "not enough data": "Not enough data yet"
  };
  var CHECK_ICONS = { pass: "✓", fail: "✕", unknown: "?", manual: "→" };
  var CHECK_LABELS = {
    pass: "Done", fail: "Needs a change", unknown: "Can't tell yet", manual: "Check it yourself"
  };
  var SIGNAL_GUIDE = "Signal guide: -55 dBm or better is great, down to -67 is good, " +
    "down to -75 is okay, below that is weak. Closer to 0 is stronger.";

  // ------------------------------------------------------------------
  // Small helpers
  // ------------------------------------------------------------------

  function readToken() {
    var meta = document.querySelector('meta[name="dash-token"]');
    return meta ? (meta.getAttribute("content") || "") : "";
  }

  function $(id) { return document.getElementById(id); }

  function setAttrs(node, attrs) {
    if (!attrs) { return; }
    Object.keys(attrs).forEach(function (key) {
      var value = attrs[key];
      if (value === null || value === undefined || value === false) { return; }
      if (key === "text") { node.textContent = String(value); return; }
      if (key === "style" || key.slice(0, 2) === "on") { return; } // never from data
      node.setAttribute(key, value === true ? "" : String(value));
    });
  }

  function append(parent, child) {
    if (child === null || child === undefined || child === false) { return; }
    if (Array.isArray(child)) {
      child.forEach(function (c) { append(parent, c); });
      return;
    }
    if (typeof child === "string" || typeof child === "number") {
      parent.appendChild(document.createTextNode(String(child)));
      return;
    }
    parent.appendChild(child);
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    setAttrs(node, attrs);
    append(node, children);
    return node;
  }

  function svgEl(tag, attrs, children) {
    var node = document.createElementNS(SVG_NS, tag);
    setAttrs(node, attrs);
    append(node, children);
    return node;
  }

  function clear(node) {
    while (node && node.firstChild) { node.removeChild(node.firstChild); }
  }

  function fill(id, children) {
    var node = $(id);
    if (!node) { return; }
    clear(node);
    append(node, children);
  }

  function obj(v) { return v && typeof v === "object" && !Array.isArray(v) ? v : null; }

  // Maps keyed by data (room names, Deco names, MACs) must not inherit from
  // Object.prototype: a room called "constructor" or "__proto__" would clash.
  function dict() { return Object.create(null); }

  // Look up a label table without picking up "toString", "constructor" and so on.
  function own(map, key) {
    return (typeof key === "string" && Object.prototype.hasOwnProperty.call(map, key)) ? map[key] : undefined;
  }
  function arr(v) { return Array.isArray(v) ? v : []; }
  function isNum(v) { return typeof v === "number" && isFinite(v); }
  function clamp01(v) { return isNum(v) ? Math.max(0, Math.min(1, v)) : 0; }

  function snap() { return (state && obj(state.snapshot)) || {}; }
  function analysis() { return (state && obj(state.analysis)) || {}; }
  function deco() { return obj(snap().deco); }

  function fmt(value, unit, digits) {
    if (!isNum(value)) { return NOT_YET; }
    var d = digits;
    if (d === undefined) { d = Math.abs(value) >= 100 ? 0 : 1; }
    var p = Math.pow(10, d);
    var rounded = Math.round(value * p) / p;
    var s = rounded.toLocaleString(undefined, { maximumFractionDigits: d });
    return unit ? s + " " + unit : s;
  }

  function fmtOr(value, unit, digits, fallback) {
    return isNum(value) ? fmt(value, unit, digits) : fallback;
  }

  function txt(value, fallback) {
    if (value === null || value === undefined || value === "" ||
        (typeof value === "number" && !isFinite(value))) {
      return fallback === undefined ? NOT_YET : fallback;
    }
    return String(value);
  }

  function yesNo(value, yes, no, unknown) {
    if (value === true) { return yes || "Yes"; }
    if (value === false) { return no || "No"; }
    return unknown || "unknown";
  }

  function fmtRate(kbps) {
    if (!isNum(kbps) || kbps <= 0) { return "0"; }
    if (kbps >= 1000) { return fmt(kbps / 1000, "Mbps", kbps >= 100000 ? 0 : 1); }
    if (kbps >= 1) { return fmt(kbps, "kbps", 0); }
    return "under 1 kbps";
  }

  function fmtTime(iso) {
    if (!iso) { return NOT_YET; }
    var d = new Date(iso);
    if (isNaN(d.getTime())) { return String(iso); }
    return d.toLocaleString([], {
      weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit"
    });
  }

  function ago(iso) {
    var d = new Date(iso);
    if (!iso || isNaN(d.getTime())) { return ""; }
    var s = Math.round((Date.now() - d.getTime()) / 1000);
    if (s < 0) { s = 0; }
    if (s < 60) { return "just now"; }
    if (s < 3600) { return Math.round(s / 60) + " min ago"; }
    if (s < 86400) { return Math.round(s / 3600) + " h ago"; }
    return Math.round(s / 86400) + " days ago";
  }

  function bandLabel(band) { return own(BAND_LABELS, band) || (band ? String(band) : "Unknown"); }

  function linkBandLabel(band) {
    if (!band) { return NOT_YET; }
    return String(band).replace(/(\d)\s*GHz/i, "$1 GHz");
  }

  function wifiGenLabel(link) {
    var gen = link.wifi_gen;
    var name = null;
    if (gen === 7) { name = "Wi-Fi 7"; }
    else if (gen === 6) { name = /6/.test(String(link.band || "")) ? "Wi-Fi 6E" : "Wi-Fi 6"; }
    else if (gen === 5) { name = "Wi-Fi 5"; }
    else if (gen === 4) { name = "Wi-Fi 4"; }
    if (name && link.phy) { return name + " (" + link.phy + ")"; }
    return name || txt(link.phy);
  }

  function modeLabel(mode) {
    if (!mode) { return "unknown"; }
    var m = String(mode).toLowerCase();
    var name = null;
    if (m.indexOf("be") >= 0) { name = "Wi-Fi 7"; }
    else if (m.indexOf("ax") >= 0) { name = "Wi-Fi 6"; }
    else if (m.indexOf("ac") >= 0) { name = "Wi-Fi 5"; }
    else if (m.indexOf("n") >= 0) { name = "Wi-Fi 4"; }
    return name ? name + " (" + mode + ")" : String(mode);
  }

  function dialLabel(type) {
    var map = {
      dynamic_ip: "Dynamic IP (gets its address automatically)",
      static_ip: "Static IP (a fixed address)",
      pppoe: "PPPoE (logs in to your provider)",
      l2tp: "L2TP", pptp: "PPTP"
    };
    return own(map, type) || txt(type, "unknown");
  }

  // ------------------------------------------------------------------
  // Little UI pieces
  // ------------------------------------------------------------------

  function kv(rows) {
    var dl = el("dl", { "class": "kv" });
    rows.forEach(function (row) {
      if (!row) { return; }
      dl.appendChild(el("dt", null, row[0]));
      dl.appendChild(el("dd", null, row[1]));
    });
    return dl;
  }

  function bar(fraction, colorClass, thin) {
    var inner = el("span");
    inner.style.width = (clamp01(fraction) * 100).toFixed(1) + "%";
    return el("div", {
      "class": "bar" + (colorClass ? " " + colorClass : "") + (thin ? " thin" : ""),
      "aria-hidden": "true"
    }, inner);
  }

  function note(text, kind) {
    return el("p", { "class": "note " + (kind || "info") }, text);
  }

  function empty(text) { return el("p", { "class": "empty" }, text); }

  function signalInfo(dbm, bars) {
    if (isNum(dbm)) {
      if (dbm >= -55) { return { cls: "s-great", bars: 4, label: "Great", stroke: "stroke-green" }; }
      if (dbm >= -67) { return { cls: "s-good", bars: 3, label: "Good", stroke: "stroke-green" }; }
      if (dbm >= -75) { return { cls: "s-ok", bars: 2, label: "Okay", stroke: "stroke-yellow" }; }
      if (dbm >= -82) { return { cls: "s-weak", bars: 1, label: "Weak", stroke: "stroke-orange" }; }
      return { cls: "s-bad", bars: 1, label: "Very weak", stroke: "stroke-red" };
    }
    if (isNum(bars) && bars > 0) {
      if (bars >= 4) { return { cls: "s-great", bars: 4, label: "Strong", stroke: "stroke-green" }; }
      if (bars >= 3) { return { cls: "s-good", bars: 3, label: "Good", stroke: "stroke-green" }; }
      if (bars >= 2) { return { cls: "s-ok", bars: 2, label: "Okay", stroke: "stroke-yellow" }; }
      return { cls: "s-weak", bars: 1, label: "Weak", stroke: "stroke-orange" };
    }
    return null;
  }

  function signalMeter(dbm, bars) {
    var info = signalInfo(dbm, bars);
    if (!info) { return el("span", { "class": "muted" }, NOT_YET); }
    var meter = el("span", { "class": "signal-bars", "aria-hidden": "true" });
    for (var i = 0; i < 4; i += 1) {
      meter.appendChild(el("i", { "class": i < info.bars ? "on" : null }));
    }
    var detail = isNum(dbm) ? dbm + " dBm" : bars + " of 5 bars";
    return el("span", { "class": "signal " + info.cls }, [
      meter,
      el("span", { "class": "signal-label" }, info.label),
      el("span", { "class": "muted" }, detail)
    ]);
  }

  function gradeClass(grade) {
    if (grade === "A+" || grade === "A") { return "gb-good"; }
    if (grade === "B" || grade === "C") { return "gb-ok"; }
    if (grade === "D" || grade === "F") { return "gb-bad"; }
    return "";
  }

  // ------------------------------------------------------------------
  // Talking to the server
  // ------------------------------------------------------------------

  function api(method, path, body) {
    var opts = {
      method: method,
      headers: { "X-Dash-Token": TOKEN },
      cache: "no-store",
      credentials: "same-origin"
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (res) {
      return res.text().then(function (raw) {
        var data = null;
        try { data = raw ? JSON.parse(raw) : null; } catch (e) { data = null; }
        return { ok: res.ok, status: res.status, data: data, res: res };
      });
    }, function () {
      throw new Error("Can't reach the dashboard. Is run.py still running in the Terminal window?");
    });
  }

  function errorText(r) {
    if (r && r.data && typeof r.data.error === "string" && r.data.error) { return r.data.error; }
    if (r && r.status === 403) {
      return "The dashboard didn't accept this page. Reload it, or open the link run.py printed.";
    }
    return "Something went wrong (HTTP " + (r ? r.status : "?") + ").";
  }

  function anyRunning(s) {
    var jobs = (s && obj(s.jobs)) || {};
    return Object.keys(jobs).some(function (k) { return jobs[k] && jobs[k].status === "running"; });
  }

  function schedulePoll() {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    if (anyRunning(state)) { pollTimer = setTimeout(refresh, 1000); }
  }

  function refresh() {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    return api("GET", "/api/state").then(function (r) {
      if (r.ok && r.data && r.data.snapshot) {
        applyState(r.data);
      } else {
        showMessage(errorText(r), "error");
        if (anyRunning(state)) { pollTimer = setTimeout(refresh, 3000); }
      }
    }).catch(function (e) {
      showMessage(e.message, "error");
      if (anyRunning(state)) { pollTimer = setTimeout(refresh, 3000); }
    });
  }

  function act(buttonId, method, path, body, handlers) {
    handlers = handlers || {};
    busy[buttonId] = true;
    updateButtons();
    return api(method, path, body).then(function (r) {
      if (r.ok && r.data && r.data.snapshot) {
        applyState(r.data);
        if (handlers.ok) { handlers.ok(r.data); }
      } else {
        var msg = errorText(r);
        if (handlers.fail) { handlers.fail(msg, r); } else { showMessage(msg, "error"); }
        refresh();
      }
    }).catch(function (e) {
      if (handlers.fail) { handlers.fail(e.message, null); } else { showMessage(e.message, "error"); }
    }).then(function () {
      delete busy[buttonId];
      updateButtons();
    });
  }

  function stableKey(s) {
    try {
      var copy = Object.assign({}, s, { snapshot: Object.assign({}, s.snapshot, { generated_at: null }) });
      return JSON.stringify(copy);
    } catch (e) {
      return String(Date.now());
    }
  }

  function applyState(next) {
    var prev = state;
    state = next;
    announceJobChanges(prev, next);
    var key = stableKey(next);
    if (key !== lastKey) {
      lastKey = key;
      render();
    } else {
      updateButtons();
    }
    schedulePoll();
  }

  function announceJobChanges(prev, next) {
    if (!prev || !prev.jobs || !next || !next.jobs) { return; }
    var errors = [];
    JOB_ORDER.forEach(function (name) {
      var a = prev.jobs[name];
      var b = next.jobs[name];
      if (!a || !b || a.status !== "running" || b.status === "running") { return; }
      if (b.status === "error") { errors.push(JOB_LABELS[name] + ": " + txt(b.message, "it didn't work.")); }
    });
    if (errors.length) {
      showMessage(errors.join(" "), "error");
      return;
    }
    if (anyRunning(prev) && !anyRunning(next)) {
      var room = next.jobs.room;
      if (room && prev.jobs.room && prev.jobs.room.status === "running" && room.status === "done") {
        showMessage(txt(room.message, "Room test saved."), "ok");
      } else {
        showMessage("Done. Your score and tips are up to date.", "ok");
      }
    }
  }

  function showMessage(text, kind, sticky) {
    var box = $("message");
    if (!box) { return; }
    box.textContent = text;
    box.className = "message" + (kind ? " " + kind : "");
    box.hidden = false;
    if (messageTimer) { clearTimeout(messageTimer); messageTimer = null; }
    if (!sticky) {
      messageTimer = setTimeout(function () { box.hidden = true; }, kind === "error" ? 14000 : 7000);
    }
  }

  function hideMessage() {
    var box = $("message");
    if (box) { box.hidden = true; }
  }

  // ------------------------------------------------------------------
  // Rendering
  // ------------------------------------------------------------------

  var SECTIONS = [
    ["header", renderHeader], ["hero", renderHero], ["jobs", renderJobs],
    ["connect", renderConnect], ["settings", renderSettings], ["findings", renderFindings],
    ["internet", renderInternet], ["computer", renderComputer], ["mesh", renderMesh],
    ["devices", renderDevices], ["wifi", renderWifi], ["wan", renderWan],
    ["checklist", renderChecklist], ["rooms", renderRooms], ["raw", renderRaw]
  ];

  function render() {
    if (!state) { return; }
    SECTIONS.forEach(function (section) {
      try {
        section[1]();
      } catch (e) {
        if (window.console && console.error) { console.error("Couldn't draw " + section[0], e); }
      }
    });
    updateButtons();
  }

  function renderHeader() {
    $("version").textContent = state.version ? "Version " + state.version : "";
    $("demo-banner").hidden = !state.demo;
    var pill = $("conn-pill");
    if (state.demo) {
      pill.className = "pill demo";
      pill.textContent = "Demo data";
    } else if (state.logged_in) {
      pill.className = "pill ok";
      pill.textContent = "Connected to Deco";
    } else {
      pill.className = "pill";
      pill.textContent = "Not connected to Deco";
    }
    document.title = (state.demo ? "DEMO - " : "") + "Deco Wi-Fi Dashboard";
  }

  function renderHero() {
    var a = analysis();
    var score = isNum(a.score) ? Math.max(0, Math.min(100, Math.round(a.score))) : null;
    var grade = (typeof a.grade === "string" && /^[A-F]$/.test(a.grade)) ? a.grade : null;
    var circumference = 2 * Math.PI * 52;
    var ring = $("ring-value");
    ring.setAttribute("stroke-dasharray", circumference.toFixed(2));
    ring.setAttribute("stroke-dashoffset",
      (score === null ? circumference : circumference * (1 - score / 100)).toFixed(2));
    var stroke = { A: "stroke-green", B: "stroke-green", C: "stroke-yellow", D: "stroke-orange", F: "stroke-red" };
    ring.setAttribute("class", "ring-value " + (grade ? stroke[grade] : "stroke-gray"));
    var gradeNode = $("score-grade");
    gradeNode.textContent = grade || "?";
    gradeNode.className = "ring-grade g-" + (grade || "none");
    $("score-num").textContent = score === null ? "no score yet" : score + " / 100";
    $("ring-label").textContent = score === null ? "No score yet" :
      "Score " + score + " out of 100, grade " + (grade || "unknown");
    $("headline").textContent = txt(a.headline, "Run a check to get your score.");

    var errNode = $("analysis-error");
    if (a.error) {
      errNode.textContent = String(a.error);
      errNode.hidden = false;
    } else {
      errNode.hidden = true;
    }

    var chip = $("bottleneck-chip");
    var b = typeof a.bottleneck === "string" ? a.bottleneck : "";
    chip.textContent = own(BOTTLENECKS, b) || (b ? "Main limit: " + b : "");
    chip.className = "chip bottleneck" + (b === "none found" ? " none" : "");
    chip.hidden = !b || b === "not enough data";

    var cov = obj(a.data_coverage) || {};
    var parts = [["deco", "Deco"], ["link", "This computer"], ["latency", "Ping"], ["speed", "Speed test"], ["dns", "DNS"]];
    var chips = parts.map(function (p) {
      var have = cov[p[0]] === true;
      return el("span", {
        "class": "chip " + (have ? "ok" : "missing"),
        "title": have ? "Measured" : "Not measured yet"
      }, p[1]);
    });
    var rooms = isNum(cov.rooms) ? cov.rooms : 0;
    chips.push(el("span", { "class": "chip " + (rooms > 0 ? "ok" : "missing") },
      rooms === 1 ? "1 room tested" : rooms + " rooms tested"));
    fill("coverage-chips", chips);
  }

  function renderJobs() {
    var jobs = obj(state.jobs) || {};
    var rows = [];
    JOB_ORDER.forEach(function (name) {
      var job = obj(jobs[name]);
      if (!job || (job.status === "idle" && !job.message)) { return; }
      var status = ["idle", "running", "done", "error"].indexOf(job.status) >= 0 ? job.status : "idle";
      var progress = status === "done" ? 1 : clamp01(job.progress);
      var inner = el("span");
      inner.style.width = Math.round(progress * 100) + "%";
      var msg = txt(job.message, "");
      if (status === "running" && !msg) { msg = "Working…"; }
      if (status === "error") { msg = "Problem: " + (msg || "it didn't work."); }
      rows.push(el("div", { "class": "job " + status }, [
        el("span", { "class": "job-name" }, JOB_LABELS[name] || name),
        el("div", {
          "class": "progress", role: "progressbar",
          "aria-label": (JOB_LABELS[name] || name) + " progress",
          "aria-valuemin": "0", "aria-valuemax": "100",
          "aria-valuenow": String(Math.round(progress * 100))
        }, inner),
        el("span", { "class": "job-msg" }, msg)
      ]));
    });
    fill("jobs", rows);
  }

  function renderConnect() {
    var s = snap();
    var settings = obj(s.settings) || {};
    var d = deco();
    var host = $("deco-host");
    if (!formsFilled && settings.deco_host && document.activeElement !== host) {
      host.value = String(settings.deco_host);
    }
    var status;
    if (state.demo) {
      status = state.logged_in ?
        "Demo mode: showing a made-up Deco. Nothing is sent anywhere." :
        "Demo mode: you can try connecting. Nothing is sent anywhere.";
    } else if (state.logged_in) {
      status = "Connected to " + txt(settings.deco_host, "your Deco") + ". Last read " +
        (d ? fmtTime(d.fetched_at) : NOT_YET) + ".";
    } else if (d) {
      status = "Not connected. Showing what we read " + (ago(d.fetched_at) || "earlier") + ".";
    } else {
      status = "Not connected yet. Connect to see your Decos and devices.";
    }
    $("connect-status").textContent = status;
    $("login-form").hidden = !!state.logged_in;
    $("connected-box").hidden = !state.logged_in;
    var err = loginError || (s.deco_error ? String(s.deco_error) : "");
    var errNode = $("login-error");
    errNode.textContent = err;
    errNode.hidden = !err;
  }

  function setInput(id, value) {
    var input = $(id);
    if (!input || document.activeElement === input) { return; }
    input.value = (value === null || value === undefined || (typeof value === "number" && !isFinite(value))) ?
      "" : String(value);
  }

  function renderSettings() {
    var settings = obj(snap().settings) || {};
    if (!formsFilled) {
      setInput("plan-down", settings.plan_down_mbps);
      setInput("plan-up", settings.plan_up_mbps);
      setInput("room-name", settings.room);
      formsFilled = true;
    }
    var roomInput = $("room-test-name");
    if (roomInput && !roomInput.value && settings.room && document.activeElement !== roomInput) {
      roomInput.value = String(settings.room);
    }
  }

  function findingNode(f) {
    var sev = own(SEV_LABELS, f.severity) ? f.severity : "low";
    var id = String(f.id || f.title || "");
    var details = el("details", { "class": "finding sev-" + sev });
    details.open = !!openFindings[id];
    details.addEventListener("toggle", function () {
      if (details.open) { openFindings[id] = true; } else { delete openFindings[id]; }
    });
    details.appendChild(el("summary", null, [
      el("span", { "class": "sev sev-" + sev }, SEV_LABELS[sev]),
      el("span", { "class": "finding-title" }, txt(f.title, "Tip")),
      f.impact ? el("span", { "class": "impact" + (f.impact === "big" ? " big" : "") },
        own(IMPACT_LABELS, f.impact) || String(f.impact)) : null
    ]));
    var body = el("div", { "class": "finding-body" });
    if (f.what_it_means) { body.appendChild(el("p", null, String(f.what_it_means))); }
    var steps = arr(f.how_to_fix).filter(function (x) { return typeof x === "string" && x; });
    if (steps.length) {
      body.appendChild(el("h4", null, sev === "good" ? "Keep it that way" : "How to fix it"));
      body.appendChild(el("ol", null, steps.map(function (step) { return el("li", null, step); })));
    }
    if (f.evidence) {
      body.appendChild(el("p", { "class": "evidence" }, [el("strong", null, "Why we think so: "), String(f.evidence)]));
    }
    if (f.category) { body.appendChild(el("p", { "class": "cat" }, "Category: " + String(f.category))); }
    details.appendChild(body);
    return details;
  }

  function renderFindings() {
    var a = analysis();
    var list = arr(a.findings).filter(obj);
    var out = [];
    var issues = list.filter(function (f) { return f.severity !== "good"; });
    var good = list.filter(function (f) { return f.severity === "good"; });
    if (!list.length) {
      out.push(empty(isNum(a.score) ? "Nothing to fix right now. Nice!" :
        "Run a check to see what to fix."));
    } else if (!issues.length) {
      out.push(empty("Nothing big to fix right now. Nice!"));
    }
    issues.forEach(function (f) { out.push(findingNode(f)); });
    if (good.length) {
      var group = el("details", { "class": "good-group" });
      group.open = !!openFindings.__good__;
      group.addEventListener("toggle", function () {
        if (group.open) { openFindings.__good__ = true; } else { delete openFindings.__good__; }
      });
      group.appendChild(el("summary", null, "What's already good (" + good.length + ")"));
      good.forEach(function (f) { group.appendChild(findingNode(f)); });
      out.push(group);
    }
    fill("findings", out);
  }

  function speedMetric(label, value, plan) {
    var fraction = 0;
    var color = "";
    var sub;
    if (isNum(value) && isNum(plan) && plan > 0) {
      fraction = value / plan;
      color = fraction >= 0.8 ? "c-green" : fraction >= 0.5 ? "c-yellow" : fraction >= 0.25 ? "c-orange" : "c-red";
      sub = Math.round(fraction * 100) + "% of your " + fmt(plan, "Mbps") + " plan";
    } else if (isNum(value)) {
      fraction = Math.min(1, value / 1000);
      sub = "Add your plan speed in Settings to compare.";
    } else {
      sub = "This part of the test didn't finish.";
    }
    return el("div", { "class": "metric" }, [
      el("div", { "class": "metric-head" }, [
        el("span", { "class": "metric-label" }, label),
        el("span", { "class": "metric-value" }, fmt(value, "Mbps"))
      ]),
      bar(fraction, color),
      el("div", { "class": "metric-sub" }, sub)
    ]);
  }

  function latencyRow(label, value, max) {
    return el("div", { "class": "metric" }, [
      el("div", { "class": "metric-head" }, [
        el("span", { "class": "metric-label" }, label),
        el("span", { "class": "small" }, fmt(value, "ms", 0))
      ]),
      bar(isNum(value) && max > 0 ? value / max : 0,
        !isNum(value) ? "c-gray" : value < 60 ? "c-green" : value < 200 ? "c-yellow" : "c-red", true)
    ]);
  }

  function targetText(t) {
    if (!obj(t)) { return NOT_YET; }
    if (!isNum(t.median_ms)) { return "no replies"; }
    var s = fmt(t.median_ms, "ms", 0);
    if (isNum(t.jitter_ms)) { s += ", jitter " + fmt(t.jitter_ms, "ms", 0); }
    if (isNum(t.loss_pct) && t.loss_pct > 0) { s += ", " + fmt(t.loss_pct, "%", 0) + " lost"; }
    return s;
  }

  function renderInternet() {
    var s = snap();
    var sp = obj(s.speed);
    var lat = obj(s.latency);
    var settings = obj(s.settings) || {};
    var out = [];
    if (!sp) {
      out.push(empty("No speed test yet. Press Run full check."));
    } else {
      out.push(speedMetric("Download", sp.down_mbps, settings.plan_down_mbps));
      out.push(speedMetric("Upload", sp.up_mbps, settings.plan_up_mbps));
      out.push(el("h3", null, "Lag when the line is busy"));
      var loads = [sp.idle_latency_ms, sp.loaded_latency_down_ms, sp.loaded_latency_up_ms].filter(isNum);
      var max = loads.length ? Math.max.apply(null, loads) * 1.1 : 0;
      out.push(latencyRow("Idle (nothing else happening)", sp.idle_latency_ms, max));
      out.push(latencyRow("While downloading", sp.loaded_latency_down_ms, max));
      out.push(latencyRow("While uploading", sp.loaded_latency_up_ms, max));
      var grade = typeof sp.bufferbloat_grade === "string" ? sp.bufferbloat_grade : null;
      out.push(el("div", { "class": "metric-head" }, [
        el("span", null, [
          el("span", { "class": "metric-label" }, "Bufferbloat: "),
          el("strong", null, isNum(sp.bufferbloat_ms) ? "+" + fmt(sp.bufferbloat_ms, "ms", 0) + " extra lag" : NOT_YET)
        ]),
        el("span", { "class": "grade-badge " + gradeClass(grade), "title": "Bufferbloat grade" }, grade || "?")
      ]));
      out.push(el("p", { "class": "hint" },
        "Bufferbloat is extra lag when your connection is busy (someone streaming or downloading). " +
        "A or A+ is great for gaming and video calls."));
      if (sp.error) { out.push(note(String(sp.error), "warn")); }
      out.push(el("p", { "class": "hint" }, "Server: " + txt(sp.server, "unknown") + ". Measured " +
        fmtTime(sp.measured_at) + "."));
    }
    out.push(el("h3", null, "Ping (how fast things answer)"));
    if (!lat) {
      out.push(empty("No ping test yet. Press Quick check."));
    } else {
      var rows = [["Your Deco", targetText(lat.gateway)]];
      arr(lat.internet).forEach(function (t) {
        if (obj(t)) { rows.push([txt(t.name, "Internet server"), targetText(t)]); }
      });
      out.push(kv(rows));
      if (lat.error) { out.push(note(String(lat.error), "warn")); }
      out.push(el("p", { "class": "hint" },
        "Lower is better. Under 30 ms to the internet is great for games. Jitter is how much it jumps around."));
    }
    fill("internet", out);
  }

  function renderComputer() {
    var link = obj(snap().link);
    var out = [];
    if (!link) {
      out.push(empty("Not checked yet. Press Quick check."));
      fill("computer", out);
      return;
    }
    if (link.type === "ethernet") {
      out.push(note("You're plugged in with a cable (Ethernet). That's the fastest, steadiest way to connect. " +
        "To test Wi-Fi in a room, unplug the cable first.", "info"));
      out.push(kv([
        ["Connection", "Ethernet cable"],
        ["Adapter", txt(link.interface, "unknown")],
        ["Link speed", fmtOr(link.tx_rate_mbps, "Mbps", 0, NOT_YET)]
      ]));
    } else if (link.type === "wifi") {
      var ssidFallback = link.os === "macos" ?
        "hidden by macOS (it needs Location permission)" : "not available";
      var connectedTo = state.link_node_name ? String(state.link_node_name) + " Deco" :
        (link.bssid ? "Access point " + link.bssid : "not available");
      var rates = (isNum(link.tx_rate_mbps) || isNum(link.rx_rate_mbps)) ?
        fmtOr(link.tx_rate_mbps, "Mbps", 0, "?") + " send / " + fmtOr(link.rx_rate_mbps, "Mbps", 0, "?") + " receive" :
        NOT_YET;
      out.push(kv([
        ["Connection", "Wi-Fi"],
        ["Network name", txt(link.ssid, ssidFallback)],
        ["Connected to", connectedTo],
        ["Band", linkBandLabel(link.band)],
        ["Channel", txt(link.channel)],
        ["Channel width", fmtOr(link.width_mhz, "MHz", 0, NOT_YET)],
        ["Wi-Fi generation", wifiGenLabel(link)],
        ["Signal", signalMeter(link.rssi_dbm)],
        isNum(link.signal_pct) ? ["Signal (Windows)", fmt(link.signal_pct, "%", 0)] : null,
        ["Noise", fmtOr(link.noise_dbm, "dBm", 0, NOT_YET)],
        ["Signal vs noise", fmtOr(link.snr_db, "dB", 0, NOT_YET)],
        ["Link rate", rates]
      ]));
      out.push(el("p", { "class": "signal-scale" }, SIGNAL_GUIDE));
      out.push(el("p", { "class": "hint" },
        "The link rate is the top speed of the radio link right now. Real speeds are usually about half of it."));
    } else {
      out.push(empty("Couldn't tell how this computer is connected."));
    }
    if (link.error) { out.push(note(String(link.error), "warn")); }
    fill("computer", out);
  }

  function bestBackhaul(node) {
    var bands = arr(node.backhaul_bands);
    var dbmMap = obj(node.signal_dbm) || {};
    var barsMap = obj(node.signal_bars) || {};
    var keys = bands.length ? bands : Object.keys(dbmMap);
    var dbm = null;
    var bars = null;
    keys.forEach(function (k) {
      if (isNum(dbmMap[k]) && (dbm === null || dbmMap[k] > dbm)) { dbm = dbmMap[k]; }
      if (isNum(barsMap[k]) && (bars === null || barsMap[k] > bars)) { bars = barsMap[k]; }
    });
    if (dbm === null && bars === null) {
      Object.keys(barsMap).forEach(function (k) {
        if (isNum(barsMap[k]) && (bars === null || barsMap[k] > bars)) { bars = barsMap[k]; }
      });
    }
    return { dbm: dbm, bars: bars };
  }

  function backhaulText(node) {
    if (node.backhaul === "wired") { return "Ethernet cable (wired backhaul)"; }
    if (node.backhaul === "wireless") {
      var bands = arr(node.backhaul_bands).map(bandLabel);
      return "Wi-Fi" + (bands.length ? " on " + bands.join(" + ") : "");
    }
    if (node.backhaul === "n/a") { return "This is the main Deco"; }
    return "unknown";
  }

  function rateText(node) {
    var rx = obj(node.rx_rate_mbps) || {};
    var tx = obj(node.tx_rate_mbps) || {};
    var parts = [];
    ["band6", "band5", "band2_4"].forEach(function (b) {
      if (isNum(rx[b]) || isNum(tx[b])) {
        parts.push(bandLabel(b) + ": " + fmtOr(rx[b], "", 0, "?") + " in / " + fmtOr(tx[b], "", 0, "?") + " out Mbps");
      }
    });
    return parts.length ? parts.join("; ") : null;
  }

  function meshWidth() {
    var vw = window.innerWidth || 1024;
    if (vw >= 700) { return 640; }
    return Math.max(320, Math.min(640, vw - 64));
  }

  function topology(nodes) {
    var byMac = dict();
    nodes.forEach(function (n) { if (n.mac) { byMac[n.mac] = n; } });
    var main = nodes.filter(function (n) { return n.role === "main"; })[0] || nodes[0];
    function parentOf(n) {
      if (n === main) { return null; }
      var p = n.parent_mac ? byMac[n.parent_mac] : null;
      return (p && p !== n) ? p : main;
    }
    function depth(n) {
      var d = 0;
      var cur = n;
      var seen = [];
      while (cur && cur !== main && d < 4 && seen.indexOf(cur) < 0) {
        seen.push(cur);
        cur = parentOf(cur);
        d += 1;
      }
      return d;
    }
    var levels = [];
    nodes.forEach(function (n) {
      var d = depth(n);
      if (!levels[d]) { levels[d] = []; }
      levels[d].push(n);
    });
    levels = levels.filter(function (l) { return l && l.length; });
    // Draw on a smaller canvas on phones so the text isn't shrunk to a few
    // pixels when the map is squeezed into a narrow screen.
    var W = meshWidth();
    var rowH = 165;
    var top = 40;
    var H = top + (levels.length - 1) * rowH + 70;
    var pos = [];
    levels.forEach(function (level, li) {
      level.forEach(function (n, i) {
        // Roughly 7.5 px per character of a 13 px bold name.
        var slot = W / (level.length + 1);
        pos.push({
          node: n, x: Math.round(W * (i + 1) / (level.length + 1)), y: top + li * rowH,
          maxChars: Math.max(8, Math.min(22, Math.floor(slot / 7.5)))
        });
      });
    });
    function where(n) {
      for (var i = 0; i < pos.length; i += 1) { if (pos[i].node === n) { return pos[i]; } }
      return null;
    }
    var svg = svgEl("svg", {
      "class": "topology", viewBox: "0 0 " + W + " " + H, role: "img",
      "aria-label": "Map of your Decos and how they connect"
    });
    var lines = svgEl("g");
    var labels = svgEl("g");
    nodes.forEach(function (n) {
      var parent = parentOf(n);
      if (!parent) { return; }
      var a = where(parent);
      var b = where(n);
      if (!a || !b) { return; }
      var cls = "topo-line ";
      var label;
      if (n.backhaul === "wired") {
        cls += "wired";
        label = "cable";
      } else if (n.backhaul === "wireless") {
        var best = bestBackhaul(n);
        var info = signalInfo(best.dbm, best.bars);
        cls += "wireless " + (info ? info.stroke : "stroke-gray");
        var bands = arr(n.backhaul_bands).map(bandLabel).join(" + ");
        label = (bands || "Wi-Fi") + (isNum(best.dbm) ? ", " + best.dbm + " dBm" : "");
      } else {
        cls += "unknown stroke-gray";
        label = "link unknown";
      }
      // Start below the parent's name and device count so the line never
      // runs through that text, and end in the middle of the child's circle.
      var y1 = a.y + 64;
      lines.appendChild(svgEl("line", { "class": cls, x1: a.x, y1: y1, x2: b.x, y2: b.y }));
      // Halfway along, pushed to the outer side of the line so it isn't crossed.
      var goesLeft = b.x < a.x;
      labels.appendChild(svgEl("text", {
        "class": "topo-link-label " + (goesLeft ? "side-left" : "side-right"),
        x: Math.round(a.x + (b.x - a.x) * 0.5) + (goesLeft ? -10 : 10),
        y: Math.round(y1 + (b.y - y1) * 0.5) + 4
      }, label));
    });
    svg.appendChild(lines);
    var nodesG = svgEl("g");
    pos.forEach(function (p) {
      var n = p.node;
      var cls = "topo-node " + (n.role === "main" ? "main" : "sat") + (n.online === false ? " offline" : "");
      nodesG.appendChild(svgEl("circle", { "class": cls, cx: p.x, cy: p.y, r: 24 }));
      nodesG.appendChild(svgEl("text", { "class": "topo-icon", x: p.x, y: p.y + 4 },
        n.role === "main" ? "MAIN" : "DECO"));
      var name = txt(n.name, "Deco");
      var maxChars = p.maxChars || 22;
      if (name.length > maxChars) { name = name.slice(0, maxChars - 1) + "…"; }
      nodesG.appendChild(svgEl("text", { "class": "topo-name", x: p.x, y: p.y + 42 }, name));
      var count = isNum(n.client_count) ? n.client_count : 0;
      nodesG.appendChild(svgEl("text", { "class": "topo-sub", x: p.x, y: p.y + 57 },
        count + (count === 1 ? " device" : " devices")));
    });
    svg.appendChild(nodesG);
    svg.appendChild(labels);
    return svg;
  }

  function nodeTile(node, nodes) {
    var parent = null;
    nodes.forEach(function (n) { if (node.parent_mac && n.mac === node.parent_mac) { parent = n; } });
    var isMain = node.role === "main";
    var online = el("span", null, [
      el("span", { "class": "status-dot " + (node.online === true ? "on" : node.online === false ? "off" : "") }),
      node.online === true ? "Online" : node.online === false ? "Offline" : "unknown",
      node.internet_online === false ? ", no internet" : ""
    ]);
    var rows = [
      ["Model", txt(node.model, "unknown")],
      ["Firmware", txt(node.fw_version, "unknown")],
      ["IP address", txt(node.ip, "unknown")],
      ["Status", online]
    ];
    if (isMain) {
      rows.push(["Internet", yesNo(node.internet_online, "Connected", "Not connected", "unknown")]);
      if (isNum(node.wired_ports)) { rows.push(["Ethernet ports", String(node.wired_ports)]); }
    } else {
      rows.push(["Linked to", parent ? txt(parent.name, "another Deco") : (isMain ? "" : "the main Deco")]);
      rows.push(["Backhaul", backhaulText(node)]);
      if (node.backhaul === "wireless") {
        var best = bestBackhaul(node);
        rows.push(["Backhaul signal", signalMeter(best.dbm, best.bars)]);
        var rates = rateText(node);
        rows.push(["Link rate", rates || NOT_YET]);
      }
      if (isNum(node.backhaul_speed_mbps)) {
        rows.push(["Backhaul speed", fmt(node.backhaul_speed_mbps, "Mbps", 0) +
          (isNum(node.backhaul_max_mbps) ? " (max " + fmt(node.backhaul_max_mbps, "Mbps", 0) + ")" : "")]);
      }
    }
    rows.push(["Devices on it", String(isNum(node.client_count) ? node.client_count : 0)]);
    return el("div", { "class": "tile" }, [
      el("div", { "class": "tile-head" }, [
        el("span", { "class": "tile-name" }, txt(node.name, "Deco")),
        el("span", { "class": "role" + (isMain ? " main" : "") }, isMain ? "Main" : "Satellite")
      ]),
      kv(rows)
    ]);
  }

  function errorList(errors) {
    var keys = Object.keys(errors || {});
    if (!keys.length) { return null; }
    return el("div", { "class": "note warn" }, [
      el("strong", null, "Some parts couldn't be read:"),
      el("ul", null, keys.map(function (k) { return el("li", null, String(errors[k])); }))
    ]);
  }

  function renderMesh() {
    var s = snap();
    var d = deco();
    var out = [];
    if (!d) {
      out.push(empty("Connect to your Deco to see each unit, how they link up, and how many devices are on each."));
      if (s.deco_error) { out.push(note(String(s.deco_error), "error")); }
      fill("mesh", out);
      return;
    }
    var nodes = arr(d.nodes).filter(obj);
    if (!nodes.length) {
      out.push(empty("The Deco didn't list any units."));
    } else {
      out.push(topology(nodes));
      out.push(el("div", { "class": "tiles" }, nodes.map(function (n) { return nodeTile(n, nodes); })));
      out.push(el("p", { "class": "signal-scale" }, SIGNAL_GUIDE));
    }
    var perf = obj(d.performance) || {};
    if (isNum(perf.cpu_pct) || isNum(perf.mem_pct)) {
      out.push(el("p", { "class": "hint" }, "Main Deco load: CPU " + fmtOr(perf.cpu_pct, "%", 0, "?") +
        ", memory " + fmtOr(perf.mem_pct, "%", 0, "?") + "."));
    }
    var errs = errorList(obj(d.errors));
    if (errs) { out.push(errs); }
    if (s.deco_error) { out.push(note(String(s.deco_error), "error")); }
    out.push(el("p", { "class": "hint" }, "Read " + fmtTime(d.fetched_at) + "."));
    fill("mesh", out);
  }

  function nodeNames() {
    var names = dict();
    var d = deco();
    arr(d && d.nodes).forEach(function (n) { if (obj(n) && n.mac) { names[n.mac] = txt(n.name, "Deco"); } });
    return names;
  }

  function clientBand(c) { return DEVICE_BANDS.indexOf(c.band) >= 0 ? c.band : "unknown"; }

  function clientNode(c, names) {
    if (c.node_mac && names[c.node_mac]) { return names[c.node_mac]; }
    if (c.node_name) { return String(c.node_name); }
    return "not sure";
  }

  function renderDevices() {
    var d = deco();
    if (!d) {
      fill("devices-summary", empty("Connect to your Deco to see every device on your network."));
      fill("devices-table", null);
      return;
    }
    var clients = arr(d.clients).filter(obj).filter(function (c) { return c.online !== false; });
    var total = clients.length;
    var counts = dict();
    DEVICE_BANDS.forEach(function (b) { counts[b] = 0; });
    clients.forEach(function (c) { counts[clientBand(c)] += 1; });
    var out = [el("p", null, total === 1 ? "1 device online." : total + " devices online.")];
    if (total) {
      var stack = el("div", { "class": "stack", "aria-hidden": "true" });
      var legend = el("div", { "class": "legend" });
      DEVICE_BANDS.forEach(function (b) {
        if (!counts[b]) { return; }
        var seg = el("span", { "class": "b-" + b, "title": bandLabel(b) + ": " + counts[b] });
        seg.style.width = (counts[b] / total * 100).toFixed(1) + "%";
        stack.appendChild(seg);
        legend.appendChild(el("span", null, [el("i", { "class": "swatch b-" + b }), bandLabel(b) + ": " + counts[b]]));
      });
      out.push(stack);
      out.push(legend);
      var names = nodeNames();
      var perNode = dict();
      clients.forEach(function (c) {
        var n = clientNode(c, names);
        perNode[n] = (perNode[n] || 0) + 1;
      });
      out.push(el("div", { "class": "per-node" }, Object.keys(perNode).sort().map(function (n) {
        return el("span", { "class": "chip" }, (n === "not sure" ? "Deco not known" : n) + ": " + perNode[n]);
      })));
    }
    fill("devices-summary", out);
    renderDevicesTable();
  }

  function renderDevicesTable() {
    var d = deco();
    if (!d) { fill("devices-table", null); return; }
    var names = nodeNames();
    var q = deviceFilter.trim().toLowerCase();
    var clients = arr(d.clients).filter(obj).filter(function (c) { return c.online !== false; });
    var total = clients.length;
    var rows = clients.filter(function (c) {
      if (!q) { return true; }
      var hay = [c.name, c.ip, c.mac, bandLabel(clientBand(c)), clientNode(c, names), c.interface]
        .map(function (x) { return x === null || x === undefined ? "" : String(x).toLowerCase(); }).join(" ");
      return hay.indexOf(q) >= 0;
    });
    function traffic(c) { return (isNum(c.down_kbps) ? c.down_kbps : 0) + (isNum(c.up_kbps) ? c.up_kbps : 0); }
    rows.sort(function (a, b) {
      var diff = traffic(b) - traffic(a);
      if (diff !== 0) { return diff; }
      return String(a.name || "").localeCompare(String(b.name || ""));
    });
    if (!total) { fill("devices-table", empty("No devices online right now.")); return; }
    var head = el("tr", null, [
      el("th", { scope: "col" }, "Device"), el("th", { scope: "col" }, "Band"), el("th", { scope: "col" }, "Deco"),
      el("th", { scope: "col", "class": "num" }, "Download"), el("th", { scope: "col", "class": "num" }, "Upload"),
      el("th", { scope: "col" }, "IP address")
    ]);
    var body = el("tbody", null, rows.map(function (c) {
      var band = clientBand(c);
      var iface = typeof c.interface === "string" && c.interface !== "main" ? c.interface : null;
      return el("tr", null, [
        el("td", { "class": "name" }, [txt(c.name, "Unnamed device"),
          iface ? el("span", { "class": "tag" }, iface === "iot" ? "IoT network" : iface === "guest" ? "Guest" : iface) : null]),
        el("td", null, [el("span", { "class": "band-dot b-" + band, "aria-hidden": "true" }), bandLabel(band)]),
        el("td", null, clientNode(c, names)),
        el("td", { "class": "num" }, fmtRate(c.down_kbps)),
        el("td", { "class": "num" }, fmtRate(c.up_kbps)),
        el("td", { "class": "mono" }, txt(c.ip, "unknown"))
      ]);
    }));
    fill("devices-table", [
      el("div", { "class": "table-wrap" }, el("table", null, [el("thead", null, head), body])),
      el("p", { "class": "hint" }, "Showing " + rows.length + " of " + total +
        " devices, busiest first. Traffic is what each device is using right now.")
    ]);
  }

  function renderWifi() {
    var d = deco();
    var wifi = obj(d && d.wifi);
    if (!wifi) {
      fill("wifi", empty("Connect to your Deco to see its Wi-Fi settings."));
      return;
    }
    var bands = obj(wifi.bands) || {};
    var order = ["band2_4", "band5", "band5_2", "band6"];
    Object.keys(bands).forEach(function (k) { if (order.indexOf(k) < 0) { order.push(k); } });
    var rows = [];
    order.forEach(function (k) {
      if (!(k in bands)) { return; }
      var cfg = obj(bands[k]);
      if (!cfg) {
        rows.push(el("tr", null, [el("td", null, bandLabel(k)), el("td", { colspan: "4", "class": "muted" }, "not on this Deco")]));
        return;
      }
      var width = isNum(cfg.width_mhz) ? cfg.width_mhz + " MHz" : txt(cfg.channel_width, "auto");
      rows.push(el("tr", null, [
        el("td", null, bandLabel(k)),
        el("td", null, yesNo(cfg.enabled, "On", "Off", "?") + (cfg.hidden === true ? " (hidden)" : "")),
        el("td", { "class": "num" }, txt(cfg.channel, "auto")),
        el("td", null, width),
        el("td", null, modeLabel(cfg.mode))
      ]));
    });
    var out = [];
    if (rows.length) {
      out.push(el("div", { "class": "table-wrap" }, el("table", null, [
        el("thead", null, el("tr", null, [
          el("th", { scope: "col" }, "Band"), el("th", { scope: "col" }, "On"),
          el("th", { scope: "col", "class": "num" }, "Channel"), el("th", { scope: "col" }, "Width"),
          el("th", { scope: "col" }, "Mode")
        ])),
        el("tbody", null, rows)
      ])));
    } else {
      out.push(empty("The Deco didn't share its band settings."));
    }
    out.push(el("h3", null, "Extras"));
    out.push(kv([
      ["Guest network", yesNo(wifi.guest_enabled, "On", "Off")],
      ["IoT network", yesNo(wifi.iot_enabled, "On", "Off")],
      ["MLO (Wi-Fi 7 multi-link)", yesNo(wifi.mlo_enabled, "On", "Off")],
      ["Same name on all bands", yesNo(wifi.same_ssid_all_bands)]
    ]));
    out.push(el("p", { "class": "hint" },
      "Width is how wide the radio channel is. Wider is faster but reaches less far and picks up more interference."));
    fill("wifi", out);
  }

  function renderWan() {
    var s = snap();
    var d = deco();
    var wan = obj(d && d.wan);
    var dns = obj(s.dns);
    var out = [];
    if (!wan) {
      out.push(empty("Connect to your Deco to see how it connects to the internet."));
    } else {
      var lan = wan.lan_ip ? String(wan.lan_ip) + (wan.lan_mask ? " / " + wan.lan_mask : "") : "unknown";
      var dnsList = arr(wan.dns).filter(function (x) { return typeof x === "string" && x; });
      out.push(kv([
        ["Connection type", dialLabel(wan.dial_type)],
        ["Deco's internet address", txt(wan.wan_ip, "unknown")],
        ["Upstream router", txt(wan.gateway, "unknown")],
        ["Double NAT", wan.double_nat === true ? "Yes: your Deco sits behind another router" :
          yesNo(wan.double_nat, "Yes", "No")],
        ["Carrier NAT (CGNAT)", yesNo(wan.cgnat)],
        ["DNS servers", dnsList.length ? dnsList.join(", ") : "automatic"],
        ["DNS set automatically", yesNo(wan.auto_dns)],
        ["IPv6", yesNo(wan.ipv6_enabled, "On", "Off")],
        ["Home network", lan]
      ]));
      if (wan.double_nat === true) {
        out.push(el("p", { "class": "hint" },
          "Double NAT means two routers in a row (your provider's box and the Deco). It can cause trouble " +
          "with online games and calls. See the tips above for how to fix it."));
      }
    }
    out.push(el("h3", null, "DNS speed"));
    if (!dns) {
      out.push(empty("No DNS test yet. Press Quick check."));
    } else {
      var samples = arr(dns.samples).filter(obj);
      var failed = samples.filter(function (x) { return x.ok === false; }).length;
      out.push(kv([
        ["Typical lookup", fmt(dns.median_ms, "ms", 0)],
        ["Lookups that failed", samples.length ? failed + " of " + samples.length : NOT_YET],
        ["DNS servers this computer uses", arr(dns.resolvers).length ? arr(dns.resolvers).join(", ") : "unknown"]
      ]));
      if (dns.error) { out.push(note(String(dns.error), "warn")); }
      out.push(el("p", { "class": "hint" },
        "DNS turns names like youtube.com into addresses. Under 50 ms is good."));
    }
    fill("wan", out);
  }

  function renderChecklist() {
    var list = arr(analysis().checklist).filter(obj);
    if (!list.length) {
      fill("checklist", el("li", { "class": "empty" }, "Run a check to fill this in."));
      return;
    }
    fill("checklist", list.map(function (item) {
      var status = own(CHECK_ICONS, item.status) ? item.status : "unknown";
      return el("li", { "class": "check" }, [
        el("span", { "class": "check-icon st-" + status, role: "img", "aria-label": CHECK_LABELS[status] },
          CHECK_ICONS[status]),
        el("span", { "class": "check-title" }, txt(item.title, "Check")),
        item.detail ? el("span", { "class": "check-detail" }, String(item.detail)) : null,
        (item.how && status !== "pass") ? el("span", { "class": "check-how" }, "How: " + String(item.how)) : null
      ]);
    }));
  }

  function renderRooms() {
    var history = arr(snap().history).filter(obj);
    if (!history.length) {
      fill("rooms-chart", empty("No room tests yet."));
      fill("rooms-table", null);
      $("btn-clear-history").hidden = true;
      return;
    }
    $("btn-clear-history").hidden = false;
    var latest = dict();
    var order = [];
    history.forEach(function (t) {
      var key = String(t.room || "").trim().toLowerCase();
      if (!key) { return; }
      if (!latest[key]) { order.push(key); }
      latest[key] = t;
    });
    var rooms = order.map(function (k) { return latest[k]; });
    var speeds = rooms.map(function (t) { return t.down_mbps; }).filter(isNum);
    var best = speeds.length ? Math.max.apply(null, speeds) : 0;
    rooms.sort(function (a, b) {
      return (isNum(b.down_mbps) ? b.down_mbps : -1) - (isNum(a.down_mbps) ? a.down_mbps : -1);
    });
    var chart = el("div", { "class": "room-chart", role: "list", "aria-label": "Download speed by room" });
    rooms.forEach(function (t) {
      var v = t.down_mbps;
      var ratio = isNum(v) && best > 0 ? v / best : 0;
      var color = !isNum(v) ? "c-gray" : ratio >= 0.75 ? "c-green" : ratio >= 0.45 ? "c-yellow" : ratio >= 0.25 ? "c-orange" : "c-red";
      var label = isNum(v) ? fmt(v, "Mbps", 0) : "no speed";
      if (isNum(t.rssi_dbm)) { label += ", " + t.rssi_dbm + " dBm"; }
      chart.appendChild(el("div", { "class": "room-row", role: "listitem" }, [
        el("span", { "class": "room-name" }, txt(t.room, "Room")),
        bar(ratio, color),
        el("span", { "class": "room-val" }, label)
      ]));
    });
    var chartOut = [el("h3", null, "Download speed by room (latest test of each)"), chart];
    if (rooms.length >= 2) {
      var weakest = rooms[rooms.length - 1];
      chartOut.push(el("p", { "class": "hint" }, "Weakest spot so far: " + txt(weakest.room, "a room") +
        ". If a room is much slower than the others, a Deco closer to it (or a better spot for the nearest one) will help."));
    }
    fill("rooms-chart", chartOut);

    var newestFirst = history.slice().reverse();
    var head = el("tr", null, ["Room", "When", "Download", "Upload", "Ping", "Deco ping", "Signal", "Band", "Width", "Deco"]
      .map(function (h, i) {
        return el("th", { scope: "col", "class": (i >= 2 && i <= 5) ? "num" : null }, h);
      }));
    var body = el("tbody", null, newestFirst.map(function (t) {
      return el("tr", null, [
        el("td", { "class": "name" }, txt(t.room, "Room")),
        el("td", null, fmtTime(t.at)),
        el("td", { "class": "num" }, fmtOr(t.down_mbps, "Mbps", 0, "–")),
        el("td", { "class": "num" }, fmtOr(t.up_mbps, "Mbps", 0, "–")),
        el("td", { "class": "num" }, fmtOr(t.latency_ms, "ms", 0, "–")),
        el("td", { "class": "num" }, fmtOr(t.gateway_latency_ms, "ms", 0, "–")),
        el("td", null, isNum(t.rssi_dbm) ? signalMeter(t.rssi_dbm) : "–"),
        el("td", null, t.band ? linkBandLabel(t.band) : "–"),
        el("td", null, fmtOr(t.width_mhz, "MHz", 0, "–")),
        el("td", null, txt(t.node_name, "–"))
      ]);
    }));
    fill("rooms-table", [
      el("h3", null, "All room tests (newest first)"),
      el("div", { "class": "table-wrap" }, el("table", null, [el("thead", null, head), body])),
      el("p", { "class": "hint" }, "A dash means that part wasn't measured in that test.")
    ]);
  }

  function renderRaw() {
    var details = $("raw-details");
    var pre = $("raw-json");
    if (!details || !pre || !details.open) { return; }
    var text = JSON.stringify(snap(), null, 2);
    if (pre.textContent !== text) { pre.textContent = text; }
  }

  function updateButtons() {
    var jobs = (state && obj(state.jobs)) || {};
    function running(name) { return !!(jobs[name] && jobs[name].status === "running"); }
    var measuring = ["link", "latency", "dns", "speed", "room"].some(running);
    function set(id, disabled) { var b = $(id); if (b) { b.disabled = !!disabled; } }
    set("btn-full", busy["btn-full"] || busy["btn-quick"] || measuring || !state);
    set("btn-quick", busy["btn-full"] || busy["btn-quick"] || measuring || !state);
    set("btn-room", busy["btn-room"] || ["room", "link", "latency", "speed"].some(running) || !state);
    set("btn-login", busy["btn-login"] || running("deco"));
    set("btn-refresh-deco", busy["btn-refresh-deco"] || running("deco"));
    set("btn-logout", busy["btn-logout"]);
    set("btn-save-settings", busy["btn-save-settings"]);
    set("btn-clear-history", busy["btn-clear-history"] || running("room"));
    set("btn-export", busy["btn-export"]);
  }

  // ------------------------------------------------------------------
  // Actions
  // ------------------------------------------------------------------

  function parsePlan(value) {
    var t = String(value || "").trim();
    if (!t) { return null; }
    var n = Number(t.replace(",", "."));
    if (!isFinite(n) || n < 0 || n > 100000) { return undefined; }
    return n === 0 ? null : n;
  }

  function onLogin(event) {
    event.preventDefault();
    var host = $("deco-host").value.trim();
    var input = $("deco-password");
    var password = input.value;
    input.value = "";
    if (!host) {
      loginError = "Type the address of your main Deco (it's often 192.168.68.1).";
      renderConnect();
      return;
    }
    if (!password) {
      loginError = "Type your Deco owner password.";
      renderConnect();
      input.focus();
      return;
    }
    loginError = "";
    renderConnect();
    showMessage("Connecting to your Deco… this can take up to 30 seconds.", "", true);
    setTimeout(refresh, 800);
    act("btn-login", "POST", "/api/login", { host: host, password: password }, {
      ok: function (data) {
        loginError = "";
        renderConnect();
        var deco = data.jobs && data.jobs.deco;
        showMessage("Connected! " + txt(deco && deco.message, ""), "ok");
      },
      fail: function (msg) {
        loginError = msg;
        hideMessage();
        renderConnect();
      }
    });
    password = null;
  }

  function planInput(id) {
    var input = $(id);
    // Firefox and Safari let you type "500 Mbps" into a number box; the browser then
    // says value is "" (badInput). Treat that as a mistake, not as "no plan".
    if (input.validity && input.validity.badInput) { return undefined; }
    return parsePlan(input.value);
  }

  function onSaveSettings(event) {
    event.preventDefault();
    var down = planInput("plan-down");
    var up = planInput("plan-up");
    if (down === undefined || up === undefined) {
      showMessage("Plan speeds should be numbers in Mbps, like 500.", "error");
      return;
    }
    var room = $("room-name").value.trim();
    act("btn-save-settings", "POST", "/api/settings",
      { plan_down_mbps: down, plan_up_mbps: up, room: room || null }, {
        ok: function () {
          formsFilled = false;
          renderSettings();
          showMessage("Settings saved.", "ok");
        }
      });
  }

  function onRoomTest(event) {
    event.preventDefault();
    var input = $("room-test-name");
    var room = input.value.trim();
    if (!room) {
      showMessage("Type the name of the room you're in first.", "error");
      input.focus();
      return;
    }
    act("btn-room", "POST", "/api/room-test", { room: room }, {
      ok: function () {
        showMessage("Testing '" + room + "'. Keep the laptop still for about 30 seconds.", "", true);
      }
    });
  }

  function onClearHistory() {
    if (!window.confirm("Delete all saved room tests? This can't be undone.")) { return; }
    act("btn-clear-history", "POST", "/api/history/clear", {}, {
      ok: function () { showMessage("Room history cleared.", "ok"); }
    });
  }

  function onExport() {
    busy["btn-export"] = true;
    updateButtons();
    fetch("/api/export", { headers: { "X-Dash-Token": TOKEN }, cache: "no-store", credentials: "same-origin" })
      .then(function (res) {
        if (!res.ok) { throw new Error("Export failed (HTTP " + res.status + ")."); }
        var cd = res.headers.get("Content-Disposition") || "";
        var m = /filename="([^"]+)"/.exec(cd);
        var name = (m ? m[1] : "decodash-export.json").replace(/[^A-Za-z0-9._-]/g, "_");
        return res.blob().then(function (blob) { return { blob: blob, name: name }; });
      })
      .then(function (r) {
        var url = URL.createObjectURL(r.blob);
        var a = el("a", { href: url, download: r.name });
        a.hidden = true;
        document.body.appendChild(a);
        a.click();
        setTimeout(function () {
          URL.revokeObjectURL(url);
          if (a.parentNode) { a.parentNode.removeChild(a); }
        }, 2000);
        showMessage("Saved " + r.name + " (passwords removed).", "ok");
      })
      .catch(function (e) {
        showMessage(e && e.message && e.message.indexOf("Export") === 0 ? e.message :
          "Can't reach the dashboard. Is run.py still running?", "error");
      })
      .then(function () {
        delete busy["btn-export"];
        updateButtons();
      });
  }

  function wire() {
    $("btn-full").addEventListener("click", function () {
      act("btn-full", "POST", "/api/run", { what: "all" }, {
        ok: function () { showMessage("Full check started. It takes about a minute.", ""); }
      });
    });
    $("btn-quick").addEventListener("click", function () {
      act("btn-quick", "POST", "/api/run", { what: "quick" }, {
        ok: function () { showMessage("Quick check started.", ""); }
      });
    });
    $("login-form").addEventListener("submit", onLogin);
    $("btn-logout").addEventListener("click", function () {
      act("btn-logout", "POST", "/api/logout", {}, {
        ok: function () {
          loginError = "";
          renderConnect();
          showMessage("Disconnected. The Deco app on your phone can log in again now.", "ok");
        }
      });
    });
    $("btn-refresh-deco").addEventListener("click", function () {
      act("btn-refresh-deco", "POST", "/api/run", { what: "deco" });
    });
    $("settings-form").addEventListener("submit", onSaveSettings);
    $("room-form").addEventListener("submit", onRoomTest);
    $("btn-clear-history").addEventListener("click", onClearHistory);
    $("btn-export").addEventListener("click", onExport);
    $("device-filter").addEventListener("input", function (e) {
      deviceFilter = String(e.target.value || "");
      try { renderDevicesTable(); } catch (err) { if (window.console) { console.error(err); } }
    });
    $("raw-details").addEventListener("toggle", function () {
      try { renderRaw(); } catch (err) { if (window.console) { console.error(err); } }
    });
    // Redraw the mesh map when the screen width changes enough to need a
    // different size (for example when a phone is turned sideways).
    var lastMeshW = meshWidth();
    var resizeTimer = null;
    if (typeof window.addEventListener !== "function") { return; }
    window.addEventListener("resize", function () {
      if (resizeTimer) { clearTimeout(resizeTimer); }
      resizeTimer = setTimeout(function () {
        var w = meshWidth();
        if (w === lastMeshW || !state) { return; }
        lastMeshW = w;
        try { renderMesh(); } catch (err) { if (window.console) { console.error(err); } }
      }, 200);
    });
  }

  function init() {
    if (!TOKEN || TOKEN === "__DASH_" + "TOKEN__") {
      showMessage("Open this page with the link run.py prints (http://127.0.0.1:8765/), not as a file.", "error", true);
      return;
    }
    wire();
    updateButtons();
    refresh();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
}());
