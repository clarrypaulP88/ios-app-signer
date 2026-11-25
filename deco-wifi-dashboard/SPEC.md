# Deco Wi-Fi Dashboard: build contract

This file is the contract between modules. Every module must follow the data
shapes here exactly. If you need a field that is not listed, add it as an
*optional* extra field and never rename or remove a listed one.

## Goals

A local web dashboard that a person runs on a computer **inside their home
network**. It:

1. Logs into a TP-Link Deco mesh (tested target: Deco BE65 / "BE11000", Wi-Fi 7,
   3 units) through the Deco's local web API, **read-only**.
2. Measures what the computer itself sees: its Wi-Fi link, latency, internet
   speed, bufferbloat, and DNS speed.
3. Runs a rules engine that turns that data into a score and a ranked list of
   plain-language fixes ("do this in the Deco app → here's why").
4. Lets the person run "room tests" (the same test from different rooms) and
   compares them, to find weak spots and bad Deco placement.

## Hard rules for all code

- **Python 3.9+ compatible.** macOS ships Python 3.9. No `match`, no
  `X | Y` type unions at runtime (put `from __future__ import annotations` at the
  top of every module, and never use `|` in `isinstance` or outside annotations).
  No `dict[str, int]` subscripted builtins outside annotations.
- **Standard library only.** `cryptography` may be used *if installed* as a fast
  path, but everything must work without it.
- **Read-only to the Deco.** Never send `"operation": "write"`, `"reboot"` or
  anything that changes settings. Only `"read"`, `"login"` and `"logout"`.
- **Never store or show secrets.** The Deco password lives only in memory.
  Wi-Fi passwords from the Deco (`password`, `psk`, `key`, `passphrase`,
  `wpa_key` and anything that looks like them) must be removed by `redact()`
  before data leaves `deco_client.py`.
- The web server binds to `127.0.0.1` only, checks the `Host` header, and
  requires a per-run random token on every `/api/*` call.
- Every network measurement has a timeout and never hangs forever.
- Tests use `unittest` (stdlib), live in `tests/`, are named `test_*.py`, and
  must not touch the real internet or a real Deco. Run them with
  `python3 -m unittest discover -s tests -v` from `deco-wifi-dashboard/`.
- User-facing text (titles, explanations, fixes, README) is written for a
  **16 to 20 year old**: short sentences, explain any jargon the first time,
  no talking down.

## File layout and owners

```
deco-wifi-dashboard/
  run.py                         entry point (server builder)
  README.md                      user guide (server builder)
  SPEC.md                        this file
  decodash/__init__.py           __version__ = "1.0.0"
  decodash/crypto.py             Deco crypto (deco builder)
  decodash/deco_client.py        Deco login + read + normalize (deco builder)
  decodash/measure/__init__.py
  decodash/measure/wifi_link.py  this computer's link (measure builder)
  decodash/measure/latency.py    (measure builder)
  decodash/measure/speedtest.py  (measure builder)
  decodash/measure/dns_check.py  (measure builder)
  decodash/knowledge.py          facts about Deco models + app menus (analyzer builder)
  decodash/analyze.py            rules engine (analyzer builder)
  decodash/demo_data.py          labelled sample snapshot (server builder)
  decodash/server.py             HTTP server + API + jobs (server builder)
  decodash/web/index.html        dashboard UI (server builder)
  decodash/web/app.js
  decodash/web/style.css
  tests/mock_deco.py             fake Deco speaking the real protocol (deco builder)
  tests/test_*.py
```

## Deco local API protocol (verified against two open-source clients)

Base URL: `http://<deco-ip>` (default `192.168.68.1`). Some firmware redirects
to `https://` with a self-signed certificate. If that happens, switch the base
URL to https for the rest of the session. Certificate checks are skipped
**only** for this local Deco connection and **only** when the host is a private
IP address.

All requests are `POST`. Login username is always `admin`. The password is the
Deco **owner** password (the TP-Link ID password used in the Deco app; manager
accounts do not work). Logging in here logs the owner out of the Deco app on
their phone, because the Deco only allows one owner session.

1. `POST {base}/cgi-bin/luci/;stok=/login?form=keys`, body `{"operation":"read"}`
   (Content-Type `application/json`). Response:
   `{"result":{"password":["<n hex>","<e hex>"]}, "error_code":0}`. This is the
   password RSA key.
   - If this returns HTTP 401, the firmware uses an older "outer session"
     protocol that this tool does not support. Raise a clear
     `DecoUnsupportedFirmware` error.
2. `POST {base}/cgi-bin/luci/;stok=/login?form=auth`, body `{"operation":"read"}`.
   Response: `{"result":{"key":["<n hex>","<e hex>"],"seq":<int>}}`. This is the
   signing RSA key and the sequence number.
3. Make an AES key and IV, each a random **16-digit decimal number with no
   leading zero**, used as ASCII bytes (16 bytes each). AES-128-CBC, PKCS#7.
4. `encrypted_password = rsa_encrypt(pw_n, pw_e, password_utf8)`.
5. Every encrypted request body is the form string
   `sign=<sign>&data=<urlencoded(data)>`, Content-Type `application/json`
   (yes, really), where:
   - `data = base64(AES_CBC(key, iv, json.dumps(payload, separators=(",",":"))))`
   - `h = md5_hex("admin" + password)`
   - `sign_text = f"k={aes_key}&i={aes_iv}&h={h}&s={seq + len(data)}"`, with
     `len(data)` the length of the base64 string *before* URL-encoding.
   - `sign = rsa_encrypt(sign_n, sign_e, sign_text_utf8)`
   - `rsa_encrypt(n, e, plaintext)`: split plaintext into chunks of
     `byte_len(n) - 11` bytes, PKCS#1 v1.5 type-2 encrypt each chunk, hex
     encode each ciphertext as a zero-padded lowercase hex string of
     `2*byte_len(n)` characters, and concatenate. `byte_len(n) = (n.bit_length()+7)//8`.
6. Login: `POST {base}/cgi-bin/luci/;stok=/login?form=login` with payload
   `{"params":{"password":encrypted_password},"operation":"login"}`.
   The response JSON is `{"data":"<base64 AES>"}`. Decrypt it to get
   `{"error_code":0,"result":{"stok":"..."}}`. Read the `sysauth=<hex>` cookie
   from `Set-Cookie`. `error_code -5002` means wrong password
   (`result.attemptsAllowed` = remaining tries). A HTTP 403 on login usually
   means someone else is logged in as owner.
7. Authenticated calls: `POST {base}/cgi-bin/luci/;stok=<stok>/<path>?form=<form>`
   with `Cookie: sysauth=<value>` and an encrypted payload as in step 5.
   The response is `{"data":"<base64 AES>"}`. Decrypt it to get
   `{"error_code":0,"result":{...}}`. Decrypted `error_code -5002`, or HTTP
   401/403, means the session expired: log in again once and retry once.
8. Logout: `admin/system?form=logout`, payload `{"operation":"logout"}`.

Read endpoints used (payload is `{"operation":"read"}` unless noted):

| Key in raw | path?form | notes |
|---|---|---|
| `device_list` | `admin/device?form=device_list` | the Deco units |
| `client_list` | `admin/client?form=client_list`, payload `{"operation":"read","params":{"device_mac":"default"}}` | all online clients |
| `wlan` | `admin/wireless?form=wlan` | per-band settings (**contains Wi-Fi passwords, so redact**) |
| `wan_ipv4` | `admin/network?form=wan_ipv4` | WAN/LAN IP info |
| `performance` | `admin/network?form=performance` | `cpu_usage`/`mem_usage` as 0..1 fractions |
| `ipv6` (optional) | `admin/network?form=wan_ipv6` | may not exist; ignore errors |

Each endpoint failing on its own must **not** stop the others. Store the
error message in `deco.errors[<key>]`.

Real payload examples (field names vary by firmware, so handle all of them):

```json
// device_list, newer firmware (Deco X50 1.8.0, 2025)
{"role":"slave","nickname":"Kids","device_ip":"192.168.71.250","mac":"F0-09-0D-FA-29-84",
 "device_model":"X50","hardware_ver":"1.0","software_ver":"1.8.0 Build 25102213 Rel. 43970",
 "inet_status":"online","group_status":"connected","previous":"F0-09-0D-FA-29-7C","port_count":3,
 "signal_strength":{"band5":-50,"band2_4":-37},
 "rx_rate_list":{"band5":960,"band2_4":412},"tx_rate_list":{"band5":1297,"band2_4":258}}
{"role":"master","nickname":"Living Room","device_ip":"192.168.68.1","mac":"F0-09-0D-FA-29-7C",
 "inet_status":"online","group_status":"connected","previous":"","signal_level":{"band5":"0","band2_4":"0"}}
// device_list, older firmware
{"role":"slave","nickname":"kitchen","custom_nickname":"<base64 or plain>","connection_type":["band2_4","band5"],
 "signal_level":{"band2_4":"3","band5":"2"},"backhual_speed":..., "backhual_max_speed":...,
 "bssid_2g":"..","bssid_5g":"..","bssid_sta_2g":"..","bssid_sta_5g":"..","previous":"<parent mac>"}
// client_list item
{"mac":"cf:51:c9:04:e1:02","up_speed":17,"down_speed":3,"wire_type":"wireless","access_host":"1",
 "connection_type":"band5","space_id":"1","ip":"192.168.68.101","client_mesh":true,"online":true,
 "name":"<base64>","interface":"main"}
// wlan
{"band2_4":{"backhaul":{"channel":10},"host":{"ssid":"<b64>","password":"<b64>","channel":10,"enable":true,
   "mode":"11ng","channel_width":"HT40","enable_hide_ssid":false},"guest":{"enable":false,...}},
 "band5_1":{"backhaul":{"channel":44},"host":{"channel":44,"enable":true,"mode":"11ac","channel_width":"HT80"}},
 "band6":{"backhaul":{"channel":37},"host":{...}}, "iot": {"host": {"enable": "off"}}}
// wan_ipv4
{"wan":{"ip_info":{"mac":"..","dns1":"192.168.1.1","dns2":"0.0.0.0","mask":"255.255.255.0",
  "gateway":"192.168.1.1","ip":"192.168.1.11"},"dial_type":"dynamic_ip","enable_auto_dns":true},
 "lan":{"ip_info":{"mac":"..","mask":"255.255.252.0","ip":"192.168.68.1"}}}
// performance
{"mem_usage":0.43,"cpu_usage":0.1}
```

Notes: `backhual` is TP-Link's own typo, so read both spellings. `signal_level`
is a small number of bars (0 = none or not applicable, roughly 1 = weak and
4 or 5 = strong). `signal_strength` is dBm (negative). Names and nicknames
are often base64: decode when the result is valid UTF-8 text, otherwise keep
the raw value. `enable` can be `true`, `1`, `"1"`, `"on"`, `"enable"`,
`"enabled"`, or `"true"` (and the matching "off" values).

## Data shapes

All of these are plain JSON-serialisable dicts. Unknown values are `null`.
Never omit a listed key.

### Snapshot (what the server holds and what `analyze()` takes)

```python
Snapshot = {
  "generated_at": "2026-11-25T22:29:00+00:00",   # ISO-8601
  "demo": False,                                  # True ONLY for demo_data
  "settings": {
    "deco_host": "192.168.68.1",
    "plan_down_mbps": 500.0 | None,   # what the internet plan promises
    "plan_up_mbps": 50.0 | None,
    "room": "Bedroom" | None,          # where the computer is right now
  },
  "deco": DecoData | None,             # None = not logged in yet
  "deco_error": str | None,
  "link": LinkInfo | None,
  "latency": LatencyResult | None,
  "speed": SpeedResult | None,
  "dns": DnsResult | None,
  "history": [RoomTest, ...],          # newest last
}
```

### DecoData (from `DecoClient.fetch_all()`)

```python
DecoData = {
  "fetched_at": iso str,
  "nodes": [Node, ...],          # main node first
  "clients": [Client, ...],
  "wifi": WifiConfig,
  "wan": WanInfo,
  "performance": {"cpu_pct": float | None, "mem_pct": float | None},   # 0..100
  "errors": {"<endpoint key>": "message", ...},
  "raw": {"device_list": ..., "client_list": ..., "wlan": ..., "wan_ipv4": ..., "performance": ..., "ipv6": ...},  # REDACTED
}

Node = {
  "mac": "F0:09:0D:FA:29:84",       # normalised: upper-case, ':' separated
  "name": "Kids",
  "model": "X50" | None,
  "hw_version": str | None,
  "fw_version": str | None,
  "ip": str | None,
  "role": "main" | "satellite",
  "online": bool | None,            # group_status == "connected"
  "internet_online": bool | None,   # inet_status in online/connected/up
  "parent_mac": str | None,         # normalised; None for main
  "backhaul": "wired" | "wireless" | "unknown" | "n/a",   # "n/a" for main
  "backhaul_bands": ["band5", "band6", "band2_4"],         # bands seen in use for backhaul
  "signal_dbm": {"band2_4": int|None, "band5": int|None, "band6": int|None},  # from signal_strength
  "signal_bars": {"band2_4": int|None, "band5": int|None, "band6": int|None}, # from signal_level (0 → None for main)
  "rx_rate_mbps": {"band2_4": ..., "band5": ..., "band6": ...},   # from rx_rate_list
  "tx_rate_mbps": {"band2_4": ..., "band5": ..., "band6": ...},   # from tx_rate_list
  "backhaul_speed_mbps": float | None,      # backhual_speed / backhaul_speed
  "backhaul_max_mbps": float | None,
  "wired_ports": int | None,
  "client_count": int,              # how many online clients are attached to this node
}
```

Backhaul rules: `connection_type` contains `"wired"` or `"ethernet"` gives
`"wired"`. It has bands, or any `signal_dbm`/`signal_bars` value exists for a
satellite, gives `"wireless"` with those bands. Otherwise `"unknown"`. Band
keys are normalised so that `band5_1`, `band5_2` and `band5` all become `band5`.

```python
Client = {
  "mac": str, "name": str, "ip": str | None, "online": bool,
  "band": "band2_4" | "band5" | "band6" | "wired" | "unknown",
  "interface": "main" | "guest" | "iot" | str | None,
  "node_mac": str | None,          # which Deco it is attached to, if known (access_host / device_mac), normalised
  "down_kbps": float, "up_kbps": float,   # current traffic; the API gives bytes/s, so kbps = bytes*8/1000
}

WifiConfig = {
  "bands": {
    "band2_4": BandCfg | None, "band5": BandCfg | None, "band6": BandCfg | None,
    # band5 = band5_1 (if a band5_2 exists, put it under "band5_2")
  },
  "guest_enabled": bool | None,     # any band guest enabled
  "iot_enabled": bool | None,
  "mlo_enabled": bool | None,       # look for keys containing "mlo"
  "same_ssid_all_bands": bool | None,
}
BandCfg = {
  "enabled": bool | None, "channel": int | None, "channel_width": "HT40" | "EHT320" | str | None,
  "width_mhz": int | None,          # parsed from channel_width: digits in the string (HT20→20, VHT160→160, EHT320→320); "auto"→None
  "mode": "11ng" | "11ax" | "11be" | str | None,
  "backhaul_channel": int | None, "hidden": bool | None,
}

WanInfo = {
  "wan_ip": str | None, "wan_mask": str | None, "gateway": str | None,
  "dial_type": "dynamic_ip" | "pppoe" | "static_ip" | str | None,
  "dns": [str, ...],                # non-empty, non-0.0.0.0
  "auto_dns": bool | None,
  "lan_ip": str | None, "lan_mask": str | None,
  "double_nat": bool | None,        # wan_ip is private (10/8, 172.16/12, 192.168/16) → True; CGNAT 100.64/10 → False but "cgnat": True
  "cgnat": bool | None,
  "ipv6_enabled": bool | None,      # from optional ipv6 endpoint; None if unknown
}
```

### LinkInfo (this computer's own connection; `measure.wifi_link.get_link_info()`)

```python
LinkInfo = {
  "os": "macos" | "windows" | "linux" | "other",
  "type": "wifi" | "ethernet" | "unknown",
  "interface": str | None,
  "ssid": str | None,               # may be None on macOS without location permission
  "bssid": str | None,
  "band": "2.4GHz" | "5GHz" | "6GHz" | None,
  "channel": int | None,
  "width_mhz": int | None,
  "phy": "802.11be" | "802.11ax" | "802.11ac" | "802.11n" | str | None,
  "wifi_gen": 7 | 6 | 5 | 4 | None,  # be=7, ax=6 (6E if 6GHz), ac=5, n=4
  "rssi_dbm": int | None,
  "noise_dbm": int | None,
  "snr_db": int | None,
  "signal_pct": int | None,          # Windows gives %
  "tx_rate_mbps": float | None,
  "rx_rate_mbps": float | None,
  "error": str | None,               # why something could not be read
}
```

### LatencyResult (`measure.latency.measure_latency(gateway_host, ...)`)

TCP-connect timing, no root needed. Gateway: port 80, falling back to 443.
Internet: 1.1.1.1:443 and 8.8.8.8:443.

```python
Target = {"name": "Your Deco" | "Cloudflare" | "Google", "host": str, "port": int,
          "samples_ms": [float, ...], "median_ms": float | None, "p90_ms": float | None,
          "jitter_ms": float | None,   # mean absolute difference between consecutive samples
          "loss_pct": float}           # failed/total*100
LatencyResult = {"gateway": Target | None, "internet": [Target, ...], "measured_at": iso, "error": str | None}
```

### SpeedResult (`measure.speedtest.run_speedtest(...)`)

Uses Cloudflare's public speed endpoints: `GET {base}/__down?bytes=N` and
`POST {base}/__up`. `base` defaults to `https://speed.cloudflare.com`. Use
several parallel streams (default 6) for a fixed time (default 8 s per
direction), and ignore the first ~1 s (ramp-up) when computing Mbps.
Measure idle latency before, and loaded latency during each direction, using
small `GET {base}/__down?bytes=0` requests or TCP connects to the same host.

```python
SpeedResult = {
  "down_mbps": float | None, "up_mbps": float | None,
  "idle_latency_ms": float | None,
  "loaded_latency_down_ms": float | None, "loaded_latency_up_ms": float | None,
  "bufferbloat_ms": float | None,       # max(loaded) - idle
  "bufferbloat_grade": "A+"|"A"|"B"|"C"|"D"|"F"|None,   # <5, <30, <60, <200, <400, else
  "server": str, "duration_s": float, "measured_at": iso, "error": str | None,
}
```

### DnsResult (`measure.dns_check.measure_dns()`)

```python
DnsResult = {"median_ms": float | None, "samples": [{"host": str, "ms": float | None, "ok": bool}],
             "resolvers": [str, ...], "measured_at": iso, "error": str | None}
```

### RoomTest (saved to `~/.decodash/history.json`, max 100 entries)

```python
RoomTest = {"room": str, "at": iso, "down_mbps": float|None, "up_mbps": float|None,
            "latency_ms": float|None,          # internet median
            "gateway_latency_ms": float|None,
            "rssi_dbm": int|None, "band": str|None, "width_mhz": int|None, "phy": str|None,
            "bssid": str|None, "node_name": str|None}   # node_name if BSSID matches a node's bssid
```

### Analysis (`analyze.analyze(snapshot) -> Analysis`)

```python
Analysis = {
  "score": int | None,             # 0..100; None when there is no data at all yet
  "grade": "A"|"B"|"C"|"D"|"F"|None,   # >=90 A, >=80 B, >=65 C, >=50 D, else F; None with score None
  "headline": str,                 # one friendly sentence
  "bottleneck": "internet plan"|"wifi signal"|"mesh backhaul"|"bufferbloat"|"device"|"dns"|"none found"|"not enough data",
  "findings": [Finding, ...],      # sorted: severity, then impact
  "checklist": [ChecklistItem, ...],
  "data_coverage": {"deco": bool, "link": bool, "latency": bool, "speed": bool, "dns": bool, "rooms": int},
}
Finding = {
  "id": "satellite_wireless_backhaul_weak",   # stable snake_case id
  "severity": "critical"|"high"|"medium"|"low"|"good",
  "category": "mesh"|"wifi"|"internet"|"devices"|"settings"|"this computer",
  "title": str,                    # short, e.g. "Your 'Kids' Deco has a weak link back to the main one"
  "what_it_means": str,            # 1-3 sentences, 16-20 y/o level
  "how_to_fix": [str, ...],        # concrete steps; Deco app menu paths when relevant
  "impact": "big"|"medium"|"small",
  "evidence": str,                 # the numbers that triggered it
}
ChecklistItem = {"id": str, "title": str, "status": "pass"|"fail"|"unknown"|"manual", "detail": str, "how": str}
```

## Server HTTP API (`decodash/server.py`)

- `GET /` gives `index.html` with the literal `__DASH_TOKEN__` replaced by the
  run token.
- `GET /static/<file>` serves files from `decodash/web/` (no path traversal).
- Every `/api/*` request must carry header `X-Dash-Token: <token>`; otherwise 403.
- Requests whose `Host` header is not `127.0.0.1:<port>` or `localhost:<port>` get 403.
- `GET /api/state` returns `{"snapshot": Snapshot (redacted), "analysis": Analysis, "jobs": {name: Job}, "logged_in": bool, "demo": bool, "version": str}`
  where `Job = {"status": "idle"|"running"|"done"|"error", "progress": 0..1, "message": str}` and the job names are `deco`, `link`, `latency`, `speed`, `dns`, `room`.
- `POST /api/login` `{"host": str, "password": str}` logs in and fetches Deco data. It returns state, or `{"error": str}` with 400/401.
- `POST /api/logout`
- `POST /api/settings` `{"plan_down_mbps": num|null, "plan_up_mbps": num|null, "room": str|null, "deco_host": str}`
- `POST /api/run` `{"what": "deco"|"link"|"latency"|"speed"|"dns"|"quick"|"all"}` starts background job(s) and returns state at once. `quick` = deco+link+latency+dns. `all` = quick+speed.
- `POST /api/room-test` `{"room": str}` runs link + latency + speed, appends a RoomTest to history, and saves it.
- `POST /api/history/clear`
- `GET /api/export` downloads the redacted snapshot + analysis as JSON.
- `run.py --demo` starts with `demo_data.build_demo_snapshot()` and shows a
  big "DEMO — sample data, not your network" banner. In demo mode the run
  buttons simulate quickly instead of touching the network.

## Function signatures (import paths are fixed)

```python
# decodash/crypto.py
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes      # adds PKCS#7
def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes     # removes PKCS#7 (raise ValueError if bad)
def rsa_encrypt_chunked(n: int, e: int, plaintext: bytes) -> str           # TP-Link style, hex string
def random_16_digit() -> str                                                # "1234567890123456", no leading 0

# decodash/deco_client.py
class DecoError(Exception)
class DecoAuthError(DecoError)            # wrong password, too many tries, or owner logged in elsewhere (403)
class DecoUnsupportedFirmware(DecoError)
class DecoConnectionError(DecoError)      # cannot reach host / timeout
class DecoClient:
    def __init__(self, host: str, password: str, username: str = "admin", timeout: float = 15.0)
        # host may be "192.168.68.1", "http://192.168.68.1" or "https://..."
    def login(self) -> None
    def fetch_all(self) -> dict          # DecoData; logs in first if needed; per-endpoint errors go to ["errors"]
    def logout(self) -> None             # best effort, never raises
def normalize_mac(value) -> str | None
def decode_name(value) -> str
def normalize_nodes(device_list: list, clients: list | None = None) -> list
def normalize_clients(client_list: list) -> list
def normalize_wlan(wlan: dict) -> dict
def normalize_wan(wan_ipv4: dict | None, ipv6: dict | None = None) -> dict
def normalize_performance(perf: dict | None) -> dict
def redact(obj)                           # deep copy with secrets replaced by "***"

# decodash/measure/wifi_link.py
def get_link_info(timeout: float = 8.0) -> dict             # LinkInfo; never raises
def parse_macos_system_profiler(json_text: str) -> dict     # partial LinkInfo fields
def parse_windows_netsh(text: str) -> dict
def parse_linux_iw(link_text: str, info_text: str = "") -> dict
def default_gateway() -> str | None                         # best effort, never raises

# decodash/measure/latency.py
def tcp_ping(host: str, port: int, timeout: float = 2.0) -> float | None   # ms or None
def measure_latency(gateway_host: str | None, count: int = 15, timeout: float = 2.0) -> dict  # LatencyResult; never raises

# decodash/measure/speedtest.py
def run_speedtest(base_url: str = "https://speed.cloudflare.com", seconds: float = 8.0,
                  streams: int = 6, progress_cb=None, timeout: float = 10.0) -> dict   # SpeedResult; never raises
    # progress_cb(fraction: float, message: str) may be None
def bufferbloat_grade(ms: float | None) -> str | None

# decodash/measure/dns_check.py
def measure_dns(hosts: list | None = None, timeout: float = 3.0) -> dict   # DnsResult; never raises

# decodash/analyze.py
def analyze(snapshot: dict) -> dict      # Analysis; never raises on missing/None data

# decodash/knowledge.py  (data the analyzer and UI use)
MODELS: dict                # model code (upper-case, e.g. "BE65") -> spec dict (name, wifi_gen, bands, max_port_gbps, supports_320mhz, supports_mlo, ...)
APP_PATHS: dict             # setting id -> human path in the Deco app, e.g. "Deco app → More → Advanced → Fast Roaming"
def model_info(model: str | None) -> dict | None

# decodash/demo_data.py
def build_demo_snapshot() -> dict        # Snapshot with "demo": True

# decodash/server.py
HISTORY_PATH  # Path; default ~/.decodash/history.json, or $DECODASH_HOME/history.json
def serve(port: int = 8765, demo: bool = False, open_browser: bool = True, deco_host: str = "192.168.68.1") -> None
```
