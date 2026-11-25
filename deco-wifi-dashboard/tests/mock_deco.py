"""A fake TP-Link Deco that speaks the real local-API protocol.

Used by the tests so they never touch a real Deco or the internet. It runs a
``ThreadingHTTPServer`` on 127.0.0.1 (random free port) in a daemon thread.

What it really checks, like a Deco would:

* The password and the request signature are RSA (PKCS#1 v1.5) encrypted with
  keys it generated itself; it decrypts them with the private keys.
* The signature must contain ``k`` and ``i`` (16-digit AES key and IV),
  ``h == md5_hex("admin" + password)`` and ``s == seq + len(data)``.
* Request bodies are AES-128-CBC encrypted with that key/IV, and so are its
  answers (``{"data": "<base64>"}``).
* Login sets a ``sysauth`` cookie and returns a ``stok``; both are required on
  every later call.
* Any operation other than ``read`` / ``login`` / ``logout`` is recorded in
  ``violations`` and never performed.

It also contains a tiny pure-Python RSA key generator (Miller-Rabin), which
the crypto tests reuse to decrypt and inspect padding.
"""

from __future__ import annotations

import base64
import collections
import copy
import hashlib
import json
import math
import os
import random
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from decodash import crypto  # noqa: E402

# ---------------------------------------------------------------------------
# Tiny RSA (test use only)
# ---------------------------------------------------------------------------

_rng = random.SystemRandom()
_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]


def is_probable_prime(n: int, rounds: int = 24) -> bool:
    """Miller-Rabin primality test with random bases."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + _rng.randrange(n - 3)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits: int) -> int:
    while True:
        candidate = _rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(candidate):
            return candidate


class RsaKey:
    """An RSA key pair with just enough methods for the mock and the tests."""

    def __init__(self, n: int, e: int, d: int) -> None:
        self.n = n
        self.e = e
        self.d = d
        self.k = (n.bit_length() + 7) // 8

    @property
    def n_hex(self) -> str:
        return format(self.n, "x")

    @property
    def e_hex(self) -> str:
        return format(self.e, "06x")

    def raw_decrypt(self, c: int) -> bytes:
        """Undo RSA (no padding check): returns the k-byte encoded block."""
        return pow(c, self.d, self.n).to_bytes(self.k, "big")

    def decrypt_chunked_hex(self, text: str) -> bytes:
        """Reverse ``crypto.rsa_encrypt_chunked``: hex blocks of 2*k chars each."""
        width = 2 * self.k
        if len(text) % width:
            raise ValueError("ciphertext hex length %d is not a multiple of %d" % (len(text), width))
        out = b""
        for off in range(0, len(text), width):
            block = self.raw_decrypt(int(text[off: off + width], 16))
            message, _ps = pkcs1_v15_unpad(block)
            out += message
        return out


def pkcs1_v15_unpad(block: bytes):
    """Check a PKCS#1 v1.5 type-2 block. Returns (message, padding_string)."""
    if len(block) < 11 or block[0] != 0 or block[1] != 2:
        raise ValueError("not a PKCS#1 v1.5 type 2 block")
    try:
        sep = block.index(0, 2)
    except ValueError:
        raise ValueError("no 0x00 separator in PKCS#1 block") from None
    ps = block[2:sep]
    if len(ps) < 8:
        raise ValueError("PKCS#1 padding string shorter than 8 bytes")
    return block[sep + 1:], ps


def generate_rsa_keypair(bits: int = 512, e: int = 65537) -> RsaKey:
    """Pure-Python RSA key generation (fine for tests, not for real security)."""
    while True:
        p = random_prime(bits // 2)
        q = random_prime(bits - bits // 2)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        return RsaKey(n, e, pow(e, -1, phi))


_KEY_CACHE = {}
_KEY_LOCK = threading.Lock()


def cached_keypair(bits: int, slot: str) -> RsaKey:
    """Keys are slow-ish to make in pure Python, so reuse them between tests."""
    with _KEY_LOCK:
        key = _KEY_CACHE.get((bits, slot))
        if key is None:
            key = generate_rsa_keypair(bits)
            _KEY_CACHE[(bits, slot)] = key
        return key


# ---------------------------------------------------------------------------
# Default fixtures: a 3-unit Deco BE65 mesh
# ---------------------------------------------------------------------------


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


MAIN_MAC = "A8-42-A1-3C-5E-10"
BEDROOM_MAC = "A8-42-A1-3C-71-24"
OFFICE_MAC = "A8-42-A1-3C-88-3A"

WIFI_PASSWORDS = (
    "PurpleOtter!2026",
    "guest-pancakes-77",
    "iot-thermo-5512",
    "mlo-laser-cats-9",
)
SSID = "Hartley-Home"


def default_fixtures() -> dict:
    main_pw, guest_pw, iot_pw, mlo_pw = WIFI_PASSWORDS
    device_list = [
        {
            # main unit, newer firmware style
            "role": "master", "nickname": "living_room", "device_ip": "192.168.68.1",
            "mac": MAIN_MAC, "device_model": "BE65", "hardware_ver": "1.0",
            "software_ver": "1.2.3 Build 20250910 Rel. 61234", "inet_status": "online",
            "group_status": "connected", "previous": "", "port_count": 4,
            "signal_level": {"band2_4": "0", "band5": "0", "band6": "0"},
            "bssid_2g": "A8:42:A1:3C:5E:11", "bssid_5g": "A8:42:A1:3C:5E:12",
            "bssid_6g": "A8:42:A1:3C:5E:13", "device_type": "HOMEWIFISYSTEM",
            "oem_id": "0F5B8A1C3D2E", "hw_id": "7A1E33C0B9D4",
        },
        {
            # satellite with wireless backhaul, NEW field style (dBm + rate lists)
            "role": "slave", "nickname": "Bedroom", "device_ip": "192.168.68.21",
            "mac": BEDROOM_MAC, "device_model": "BE65", "hardware_ver": "1.0",
            "software_ver": "1.2.3 Build 20250910 Rel. 61234", "inet_status": "online",
            "group_status": "connected", "previous": MAIN_MAC, "port_count": 4,
            "signal_strength": {"band6": -63, "band5": -58},
            "rx_rate_list": {"band6": 2161, "band5": 1441},
            "tx_rate_list": {"band6": 2401, "band5": 1297},
            "bssid_2g": "A8:42:A1:3C:71:25", "bssid_5g": "A8:42:A1:3C:71:26",
            "bssid_6g": "A8:42:A1:3C:71:27", "device_type": "HOMEWIFISYSTEM",
        },
        {
            # satellite with an Ethernet backhaul, OLD field style
            "role": "slave", "nickname": "office", "custom_nickname": b64("Office"),
            "device_ip": "192.168.68.35", "mac": OFFICE_MAC, "device_model": "BE65",
            "hardware_ver": "1.0", "software_ver": "1.1.9 Build 20250401 Rel. 50318",
            "inet_status": "online", "group_status": "connected", "previous": MAIN_MAC,
            "connection_type": ["wired"], "signal_level": {"band2_4": "0", "band5": "0"},
            "backhual_speed": 2500, "backhual_max_speed": 2500,
            "bssid_2g": "A8:42:A1:3C:88:3B", "bssid_5g": "A8:42:A1:3C:88:3C",
            "bssid_sta_2g": "", "bssid_sta_5g": "", "device_type": "HOMEWIFISYSTEM",
        },
    ]

    def client(mac, name, band, interface, ip, down, up, online=True, plain_name=False):
        wired = band == "wired"
        item = {
            "mac": mac, "up_speed": up, "down_speed": down,
            "wire_type": "wired" if wired else "wireless", "access_host": "1",
            "connection_type": band, "space_id": "1", "ip": ip, "online": online,
            "name": name if plain_name else b64(name), "enable_priority": False,
            "remain_time": 0, "owner_id": "", "client_type": "other", "interface": interface,
        }
        if not wired:
            item["client_mesh"] = True
        return item

    clients = [
        (client("3c:22:fb:10:aa:01", "Maya's iPhone 15", "band6", "main", "192.168.68.101", 1250000, 40000), BEDROOM_MAC),
        (client("f0:18:98:2b:4c:02", "MacBook Air", "band5", "main", "192.168.68.102", 310000, 52000), MAIN_MAC),
        (client("a4:30:7a:55:61:03", "Living Room TV", "band5", "main", "192.168.68.103", 2100000, 9000), MAIN_MAC),
        (client("00:d9:d1:7e:12:04", "PS5", "wired", "main", "192.168.68.104", 520000, 31000), OFFICE_MAC),
        (client("44:00:49:0a:bc:05", "Echo Dot", "band2_4", "iot", "192.168.68.105", 1200, 800), MAIN_MAC),
        (client("90:48:6c:33:de:06", "Ring Doorbell", "band2_4", "iot", "192.168.68.106", 4000, 61000), OFFICE_MAC),
        (client("da:a1:19:77:f0:07", "Sam's Pixel 8", "band5", "guest", "192.168.68.107", 88000, 7000), BEDROOM_MAC),
        (client("74:75:48:3f:20:08", "Kindle", "band2_4", "main", "192.168.68.108", 0, 0, plain_name=True), BEDROOM_MAC),
        (client("6c:4a:85:c1:09:09", "Old iPad", "band5", "main", "192.168.68.109", 0, 0, online=False), BEDROOM_MAC),
    ]

    def host_cfg(channel, mode, width, enable, hide=False):
        return {"ssid": b64(SSID), "password": b64(main_pw), "channel": channel, "enable": enable,
                "mode": mode, "channel_width": width, "enable_hide_ssid": hide}

    def guest_cfg(enable):
        return {"ssid": b64("Hartley-Guest"), "password": b64(guest_pw), "vlan_id": 591,
                "enable": enable, "need_set_vlan": False}

    wlan = {
        "band2_4": {"backhaul": {"channel": 6}, "host": host_cfg(6, "11bgnaxbe", "HT20", True),
                    "guest": guest_cfg(True)},
        "band5_1": {"backhaul": {"channel": 149}, "host": host_cfg(36, "11anacaxbe", "EHT160", "1"),
                    "guest": guest_cfg(False)},
        "band6": {"backhaul": {"channel": 37}, "host": host_cfg(37, "11axbe", "EHT320", "on", "off"),
                  "guest": guest_cfg("off")},
        "iot": {"host": {"ssid": b64("Hartley-IoT"), "password": b64(iot_pw), "enable": "on",
                         "band": "band2_4"}},
        # Illustrative Wi-Fi 7 MLO network block (field names vary by firmware).
        "mlo": {"host": {"ssid": b64("Hartley-MLO"), "password": b64(mlo_pw), "enable": "enabled",
                         "bands": ["band5", "band6"]}},
        "is_eg": False,
    }

    wan_ipv4 = {
        "wan": {
            "ip_info": {"mac": "A8:42:A1:3C:5E:14", "dns1": "192.168.1.1", "dns2": "0.0.0.0",
                        "mask": "255.255.255.0", "gateway": "192.168.1.1", "ip": "192.168.1.23"},
            "dial_type": "dynamic_ip", "info": {}, "enable_auto_dns": True,
        },
        "lan": {"ip_info": {"mac": "A8:42:A1:3C:5E:10", "mask": "255.255.252.0", "ip": "192.168.68.1"}},
    }

    return {
        "device_list": device_list,
        "client_list": [c for c, _node in clients],
        # which node each client is attached to (node MAC exactly as device_list has it)
        "client_nodes": {c["mac"]: node for c, node in clients},
        "wlan": wlan,
        "wan_ipv4": wan_ipv4,
        "performance": {"mem_usage": 0.61, "cpu_usage": 0.27},
        # "wan_ipv6" left out on purpose: many firmwares don't have it.
    }


# ---------------------------------------------------------------------------
# The mock server
# ---------------------------------------------------------------------------

ALLOWED_OPERATIONS = ("read", "login", "logout")


class _Handler(BaseHTTPRequestHandler):
    server_version = "lighttpd"
    sys_version = ""

    def log_message(self, fmt, *args):  # keep test output clean
        pass

    def do_POST(self):
        self.server.mock._handle_post(self)

    def _not_allowed(self):
        self.server.mock._record_violation("HTTP %s %s" % (self.command, self.path))
        self.server.mock._send(self, 405, {"error_code": -1})

    do_GET = do_PUT = do_DELETE = do_PATCH = do_HEAD = _not_allowed


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MockDeco:
    """Fake Deco. ``start()`` returns the base URL, ``stop()`` shuts it down.

    Knobs (set them as attributes, before or after ``start()``):

    * ``expire_session_after`` (int or None): after N authenticated calls,
      answer the next one with an encrypted ``error_code -5002`` (once).
    * ``expire_mode``: ``"error_code"`` (default), or 401 / 403 to end the
      session with that HTTP status instead.
    * ``keys_status`` (int or None): HTTP status for ``login?form=keys``
      (401 = unsupported "outer session" firmware).
    * ``login_forbidden``: answer the login with HTTP 403.
    * ``attempts_allowed``: tries left before lock-out (wrong passwords count down).
    * ``fail_forms``: {form, "client_list:<device_mac>" (incl. "client_list:default")
      or "client_list:per_node": HTTP status}.
    * ``delay_forms``: {form: seconds} to answer slowly.

    Inspect: ``counters`` (Counter), ``requests`` (list of dicts),
    ``violations`` (non read/login/logout operations), ``protocol_errors``.
    """

    def __init__(self, password: str = "correct horse", fixtures: dict | None = None,
                 password_key_bits: int = 1024, sign_key_bits: int = 512,
                 tls_certfile: str | None = None, tls_keyfile: str | None = None) -> None:
        self.password = password
        self.fixtures = copy.deepcopy(fixtures) if fixtures is not None else default_fixtures()
        self.expire_session_after = None
        self.expire_mode = "error_code"
        self.keys_status = None
        self.login_forbidden = False
        self.attempts_allowed = 10
        self.fail_forms = {}
        self.delay_forms = {}
        self.invalid_session_status = 403

        self.counters = collections.Counter()
        self.requests = []
        self.violations = []
        self.protocol_errors = []

        self.password_key = cached_keypair(password_key_bits, "password")
        self.sign_key = cached_keypair(sign_key_bits, "sign")
        self.seq = 100000000 + secrets.randbelow(800000000)

        self._tls = (tls_certfile, tls_keyfile) if tls_certfile else None
        self._session = None
        self._expiry_done = False
        self._lock = threading.RLock()
        self._server = None
        self._thread = None
        self.base_url = None

    # -- lifecycle -------------------------------------------------------------

    def start(self) -> str:
        server = _Server(("127.0.0.1", 0), _Handler)
        server.mock = self
        scheme = "http"
        if self._tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self._tls[0], self._tls[1])
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            scheme = "https"
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                                        name="MockDeco", daemon=True)
        self._thread.start()
        self.base_url = "%s://127.0.0.1:%d" % (scheme, server.server_address[1])
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    @property
    def session_active(self) -> bool:
        return self._session is not None

    @property
    def current_stok(self):
        return self._session["stok"] if self._session else None

    @property
    def current_sysauth(self):
        return self._session["sysauth"] if self._session else None

    # -- helpers -----------------------------------------------------------------

    def _record_violation(self, text: str) -> None:
        with self._lock:
            self.violations.append(text)

    def _protocol_error(self, text: str) -> None:
        with self._lock:
            self.protocol_errors.append(text)

    @staticmethod
    def _send(h, status: int, obj, cookie: str | None = None) -> None:
        body = json.dumps(obj).encode("utf-8")
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(body)))
        if cookie:
            h.send_header("Set-Cookie", "sysauth=%s; path=/cgi-bin/luci; HttpOnly" % cookie)
        h.end_headers()
        try:
            h.wfile.write(body)
        except OSError:
            pass

    @staticmethod
    def _encrypt(key: str, iv: str, obj) -> dict:
        text = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        enc = crypto.aes_cbc_encrypt(key.encode("ascii"), iv.encode("ascii"), text)
        return {"data": base64.b64encode(enc).decode("ascii")}

    def _parse_signed_body(self, body: str):
        """Return (sign_fields, payload_dict, data_b64) or raise ValueError."""
        pairs = urllib.parse.parse_qs(body, keep_blank_values=True, strict_parsing=True)
        if set(pairs) != {"sign", "data"}:
            raise ValueError("body must be exactly sign=...&data=..., got keys %s" % sorted(pairs))
        sign_hex = pairs["sign"][0]
        data_b64 = pairs["data"][0]
        if not re.fullmatch(r"[0-9a-f]+", sign_hex):
            raise ValueError("sign must be lower-case hex")
        sign_text = self.sign_key.decrypt_chunked_hex(sign_hex).decode("utf-8")
        fields = dict(urllib.parse.parse_qsl(sign_text, keep_blank_values=True))
        for name in ("h", "s"):
            if name not in fields:
                raise ValueError("sign is missing %r" % name)
        return fields, data_b64

    def _check_sign(self, fields: dict, data_b64: str) -> None:
        if int(fields["s"]) != self.seq + len(data_b64):
            raise ValueError("bad s: %s != seq + len(data) = %d" % (fields["s"], self.seq + len(data_b64)))
        for name in ("k", "i"):
            value = fields.get(name)
            if value is not None and not re.fullmatch(r"[1-9][0-9]{15}", value):
                raise ValueError("%s must be a 16-digit number without a leading zero" % name)

    def _decrypt_payload(self, key: str, iv: str, data_b64: str) -> dict:
        # validate=True: an un-encoded '+' arrives as a space (like on a real Deco) and is refused.
        raw = crypto.aes_cbc_decrypt(key.encode("ascii"), iv.encode("ascii"),
                                     base64.b64decode(data_b64, validate=True))
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("payload is not a JSON object")
        return payload

    @staticmethod
    def _cookie_value(h):
        header = h.headers.get("Cookie") or ""
        match = re.search(r"(?:^|;\s*)sysauth=([^;]+)", header)
        return match.group(1) if match else None

    # -- request handling ----------------------------------------------------------

    def _handle_post(self, h) -> None:
        length = int(h.headers.get("Content-Length") or 0)
        body = h.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        match = re.match(r"^/cgi-bin/luci/;stok=([^/]*)/([^?]*)(?:\?(.*))?$", h.path)
        if not match:
            self._protocol_error("unexpected path %s" % h.path)
            self._send(h, 404, {"error_code": -1})
            return
        stok, path, query = match.groups()
        form = urllib.parse.parse_qs(query or "").get("form", [""])[0]
        ctype = (h.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._protocol_error("%s?form=%s sent Content-Type %r" % (path, form, ctype))

        delay = self.delay_forms.get(form)
        if delay:
            time.sleep(delay)

        with self._lock:
            self.counters["requests"] += 1
            if path == "login":
                self._handle_login(h, stok, form, body)
            else:
                self._handle_authenticated(h, stok, path, form, body)

    def _handle_login(self, h, stok: str, form: str, body: str) -> None:
        if stok:
            self._protocol_error("login step %s sent a stok" % form)
        if form in ("keys", "auth"):
            self.counters[form] += 1
            try:
                payload = json.loads(body)
            except ValueError:
                payload = None
            op = payload.get("operation") if isinstance(payload, dict) else None
            self.requests.append({"path": "login", "form": form, "operation": op, "params": None})
            if op != "read":
                self._record_violation("login?form=%s operation=%r" % (form, op))
            if form == "keys":
                if self.keys_status:
                    self._send(h, int(self.keys_status), {"error_code": int(self.keys_status)})
                    return
                self._send(h, 200, {"error_code": 0, "result": {
                    "username": "", "password": [self.password_key.n_hex, self.password_key.e_hex]}})
            else:
                self._send(h, 200, {"error_code": 0, "result": {
                    "key": [self.sign_key.n_hex, self.sign_key.e_hex], "seq": self.seq}})
            return
        if form != "login":
            self._protocol_error("unknown login form %r" % form)
            self._send(h, 404, {"error_code": -1})
            return

        self.counters["login_attempts"] += 1
        if self.login_forbidden:
            self.counters["login_forbidden"] += 1
            self._send(h, 403, {"error_code": 403})
            return
        try:
            fields, data_b64 = self._parse_signed_body(body)
            self._check_sign(fields, data_b64)
            if "k" not in fields or "i" not in fields:
                raise ValueError("login sign must carry k and i")
            key, iv = fields["k"], fields["i"]
            payload = self._decrypt_payload(key, iv, data_b64)
        except Exception as err:
            self._protocol_error("login: %s" % err)
            self._send(h, 400, {"error_code": -1})
            return
        op = payload.get("operation")
        self.requests.append({"path": "login", "form": "login", "operation": op, "params": None})
        if op != "login":
            self._record_violation("login?form=login operation=%r" % (op,))
            self._send(h, 200, self._encrypt(key, iv, {"error_code": -1}))
            return
        try:
            enc_pw = payload["params"]["password"]
            given = self.password_key.decrypt_chunked_hex(enc_pw).decode("utf-8")
        except Exception as err:
            self._protocol_error("login password: %s" % err)
            self._send(h, 200, self._encrypt(key, iv, {"error_code": -1}))
            return
        expected_h = hashlib.md5(("admin" + self.password).encode("utf-8")).hexdigest()
        if given != self.password or self.attempts_allowed <= 0:
            self.counters["login_wrong_password"] += 1
            if self.attempts_allowed > 0:
                self.attempts_allowed -= 1
            self._send(h, 200, self._encrypt(key, iv, {
                "error_code": -5002,
                "result": {"attemptsAllowed": self.attempts_allowed, "failureCount": 1}}))
            return
        if fields["h"] != expected_h:
            self._protocol_error("login: h is not md5('admin' + password)")
            self._send(h, 200, self._encrypt(key, iv, {"error_code": -1}))
            return
        self.counters["login_ok"] += 1
        self._session = {"stok": secrets.token_hex(16), "sysauth": secrets.token_hex(16),
                         "key": key, "iv": iv}
        self._send(h, 200, self._encrypt(key, iv, {"error_code": 0, "result": {"stok": self._session["stok"]}}),
                   cookie=self._session["sysauth"])

    def _handle_authenticated(self, h, stok: str, path: str, form: str, body: str) -> None:
        session = self._session
        if session is None or stok != session["stok"] or self._cookie_value(h) != session["sysauth"]:
            self.counters["unauthorized"] += 1
            self._send(h, int(self.invalid_session_status), {"error_code": int(self.invalid_session_status)})
            return
        try:
            fields, data_b64 = self._parse_signed_body(body)
            self._check_sign(fields, data_b64)
            key = fields.get("k") or session["key"]
            iv = fields.get("i") or session["iv"]
            expected_h = hashlib.md5(("admin" + self.password).encode("utf-8")).hexdigest()
            if fields["h"] != expected_h:
                raise ValueError("h is not md5('admin' + password)")
            payload = self._decrypt_payload(key, iv, data_b64)
        except Exception as err:
            self._protocol_error("%s?form=%s: %s" % (path, form, err))
            self._send(h, 400, {"error_code": -1})
            return

        op = payload.get("operation")
        params = payload.get("params") if isinstance(payload.get("params"), dict) else None
        self.requests.append({"path": path, "form": form, "operation": op, "params": params})
        if op not in ALLOWED_OPERATIONS:
            self._record_violation("%s?form=%s operation=%r" % (path, form, op))
            self._send(h, 200, self._encrypt(key, iv, {"error_code": -1}))
            return

        if path == "admin/system" and form == "logout":
            if op != "logout":
                self._record_violation("logout with operation=%r" % (op,))
            self.counters["logout"] += 1
            self._session = None
            self._send(h, 200, self._encrypt(key, iv, {"error_code": 0, "result": {}}))
            return
        if op != "read":
            self._protocol_error("%s?form=%s used operation %r" % (path, form, op))

        self.counters["authenticated_calls"] += 1
        self.counters["read"] += 1
        self.counters["form:" + form] += 1

        if (self.expire_session_after is not None and not self._expiry_done
                and self.counters["authenticated_calls"] > int(self.expire_session_after)):
            self._expiry_done = True
            self.counters["expired_sent"] += 1
            self._session = None
            if self.expire_mode in (401, 403):
                self._send(h, int(self.expire_mode), {"error_code": int(self.expire_mode)})
            else:
                self._send(h, 200, self._encrypt(key, iv, {"error_code": -5002}))
            return

        device_mac = params.get("device_mac") if params else None
        fail_keys = [form]
        if form == "client_list":
            fail_keys.append("client_list:%s" % (device_mac or "default"))
            if device_mac not in (None, "default"):
                fail_keys.append("client_list:per_node")
        for fk in fail_keys:
            if fk in self.fail_forms:
                self._send(h, int(self.fail_forms[fk]), {"error_code": -1})
                return

        result = self._result_for(path, form, device_mac)
        if result is None:
            self._send(h, 200, self._encrypt(key, iv, {"error_code": -1}))
            return
        self._send(h, 200, self._encrypt(key, iv, {"error_code": 0, "result": result}))

    def _result_for(self, path: str, form: str, device_mac):
        fx = self.fixtures
        if path == "admin/device" and form == "device_list":
            return {"device_list": copy.deepcopy(fx.get("device_list", []))}
        if path == "admin/client" and form == "client_list":
            clients = copy.deepcopy(fx.get("client_list", []))
            if device_mac in (None, "default"):
                return {"client_list": clients}
            known = [d.get("mac") for d in fx.get("device_list", [])]
            if device_mac not in known:
                self.counters["client_list_unknown_mac"] += 1
                return {"client_list": []}
            nodes = fx.get("client_nodes", {})
            return {"client_list": [c for c in clients if nodes.get(c.get("mac")) == device_mac]}
        if path == "admin/wireless" and form == "wlan":
            return copy.deepcopy(fx.get("wlan", {}))
        if path == "admin/network" and form in ("wan_ipv4", "performance", "wan_ipv6"):
            if form not in fx:
                return None
            return copy.deepcopy(fx[form])
        return None


class RedirectServer:
    """Answers every request with a redirect to ``target_base`` + the same path."""

    def __init__(self, target_base: str, status: int = 307) -> None:
        self.target_base = target_base.rstrip("/")
        self.status = status
        self.hits = 0
        self._server = None
        self._thread = None
        self.base_url = None

    def start(self) -> str:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def _redirect(self):
                outer.hits += 1
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                self.send_response(outer.status)
                self.send_header("Location", outer.target_base + self.path)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_POST = do_GET = _redirect

        server = _Server(("127.0.0.1", 0), Handler)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                                        name="Redirect", daemon=True)
        self._thread.start()
        self.base_url = "http://127.0.0.1:%d" % server.server_address[1]
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
