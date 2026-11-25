"""Read-only client for the TP-Link Deco local web API, plus data normalisers.

This module logs into the main Deco the same way the Deco web page does,
reads a handful of status endpoints, and turns the raw firmware answers into
the tidy ``DecoData`` shape described in SPEC.md.

Safety rules this module follows:

* Read-only. Only the operations ``read``, ``login`` and ``logout`` can ever be
  sent (enforced in ``_encode_payload``).
* The Deco password lives only in memory, inside the client object. It never
  goes into returned data, error messages or logs.
* Wi-Fi passwords and other secrets in raw answers are replaced with "***" by
  ``redact()`` before anything leaves this module.
* Every network call has a timeout. Proxies from the environment are ignored,
  because the Deco is on the local network.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import crypto

__all__ = [
    "DecoError",
    "DecoAuthError",
    "DecoUnsupportedFirmware",
    "DecoConnectionError",
    "DecoClient",
    "normalize_mac",
    "decode_name",
    "normalize_band",
    "parse_enable",
    "normalize_nodes",
    "normalize_clients",
    "normalize_wlan",
    "normalize_wan",
    "normalize_performance",
    "redact",
]

DEFAULT_USERNAME = "admin"
ALLOWED_OPERATIONS = frozenset({"read", "login", "logout"})

# raw key, path, form, extra params, friendly label
ENDPOINTS = (
    ("device_list", "admin/device", "device_list", None, "the list of Deco units"),
    ("client_list", "admin/client", "client_list", {"device_mac": "default"}, "the list of connected devices"),
    ("wlan", "admin/wireless", "wlan", None, "the Wi-Fi settings"),
    ("wan_ipv4", "admin/network", "wan_ipv4", None, "the internet connection info"),
    ("performance", "admin/network", "performance", None, "the Deco's CPU and memory use"),
    ("ipv6", "admin/network", "wan_ipv6", None, "the IPv6 settings"),
)
OPTIONAL_ENDPOINTS = frozenset({"ipv6"})
PER_NODE_KEY = "client_list_per_node"

BANDS = ("band2_4", "band5", "band6")
_BAND_ORDER = {"band6": 0, "band5": 1, "band2_4": 2}

_SESSION_EXPIRED_CODES = (-5002,)
_WRONG_PASSWORD_CODE = -5002

_COOKIE_RE = re.compile(r"sysauth=([^;,\s]+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class DecoError(Exception):
    """Something went wrong talking to the Deco."""


class DecoAuthError(DecoError):
    """Wrong password, too many tries, or the owner is logged in elsewhere (403)."""


class DecoUnsupportedFirmware(DecoError):
    """The Deco speaks a login protocol this tool does not support."""


class DecoConnectionError(DecoError):
    """The Deco could not be reached, or it did not answer in time."""


class _SessionExpired(DecoError):
    """Internal: the Deco ended our session; log in again and retry once."""


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn every 30x into an HTTPError so we can handle it ourselves.

    urllib would turn a POST into a GET on 301/302/303 and refuses 307/308
    for POST, so redirects are handled explicitly in ``DecoClient._post``.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


# Where a home Deco can live. An explicit list on purpose: ``ip.is_private`` also
# covers globally reachable ranges (6to4 2002::/16, Teredo 2001::/32, and on
# Python 3.9.6 every IPv4-mapped ::ffff:a.b.c.d), and its meaning changes
# between Python versions.
_LOCAL_DECO_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918 private
    "169.254.0.0/16", "127.0.0.0/8",                   # IPv4 link-local, loopback
    "fc00::/7", "fe80::/10", "::1/128",                # IPv6 unique-local, link-local, loopback
))


def _is_private_ip_literal(host: str | None) -> bool:
    """True only for IP literals in private, link-local or loopback ranges."""
    if not host or not isinstance(host, str):
        return False
    text = host.strip().strip("[]")
    if "%" in text:  # IPv6 zone id, e.g. fe80::1%en0
        text = text.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return any(ip in net for net in _LOCAL_DECO_NETS)


def _tls_context_for(host: str | None) -> ssl.SSLContext:
    """Default verification, except for a private/link-local IP literal.

    Decos that switch to https use a self-signed certificate, so checking it
    can never work. We only skip the check when the address is a private IP
    typed as numbers (a local Deco); for any other host the normal checks apply.
    """
    ctx = ssl.create_default_context()
    if _is_private_ip_literal(host):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _md5_hex(text: str) -> str:
    data = text.encode("utf-8")
    try:
        return hashlib.md5(data, usedforsecurity=False).hexdigest()
    except TypeError:  # pragma: no cover - very old OpenSSL builds
        return hashlib.md5(data).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _finite_float(text: str):
    """json ``parse_float``: 1e400 would become inf, which is not valid JSON later."""
    value = float(text)
    return value if value == value and value not in (float("inf"), float("-inf")) else None


def _loads(text: str):
    """json.loads that turns NaN / Infinity (which Python accepts) into None."""
    return json.loads(text, parse_constant=lambda _name: None, parse_float=_finite_float)


def _has_surrogates(text: str) -> bool:
    """True if ``text`` can't be encoded as UTF-8 (lone surrogates, e.g. from bad JSON)."""
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _netloc(hostname: str, port: int | None) -> str:
    """Rebuild host[:port] so user names / passwords in a URL are never kept."""
    host = "[%s]" % hostname if ":" in hostname else hostname
    return host if port is None else "%s:%d" % (host, port)


def _error_code(data) -> object:
    if not isinstance(data, dict):
        return None
    code = data.get("error_code")
    if code is None:
        code = data.get("errorcode")
    if isinstance(code, str):
        stripped = code.strip()
        if re.fullmatch(r"-?\d+", stripped):
            return int(stripped)
        return stripped or None
    if isinstance(code, bool):
        return int(code)
    return code


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class DecoClient:
    """Log into a Deco (owner account) and read its status. Read-only."""

    def __init__(self, host: str, password: str, username: str = DEFAULT_USERNAME,
                 timeout: float = 15.0) -> None:
        text = (host or "").strip() if isinstance(host, str) else ""
        if not text:
            raise DecoConnectionError(
                "Type the IP address of your main Deco first (it is often 192.168.68.1)."
            )
        if "://" not in text:
            try:  # a bare IPv6 address needs [brackets] in a URL
                if ipaddress.ip_address(text.split("%", 1)[0]).version == 6:
                    text = "[%s]" % text
            except ValueError:
                pass
            text = "http://" + text
        bad_address = DecoConnectionError(
            "That doesn't look like a Deco address. Use something like 192.168.68.1."
        )
        parsed = urllib.parse.urlparse(text)
        try:
            port = parsed.port
        except ValueError:
            raise bad_address from None
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise bad_address
        self._base = "%s://%s" % (parsed.scheme, _netloc(parsed.hostname, port))
        self.host = parsed.hostname
        self._password = password if isinstance(password, str) else ""
        self._username = username or DEFAULT_USERNAME
        try:
            self.timeout = float(timeout)
        except (TypeError, ValueError):
            self.timeout = 15.0
        if not self.timeout > 0:
            self.timeout = 15.0
        self._lock = threading.RLock()
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),  # the Deco is local: never use a proxy
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=_tls_context_for(self.host)),
        )
        self._clear_session()

    # -- small public helpers ------------------------------------------------

    @property
    def base_url(self) -> str:
        """Current base URL (switches to https if the Deco redirects us)."""
        return self._base

    @property
    def logged_in(self) -> bool:
        return bool(self._stok) and bool(self._cookie)

    def __repr__(self) -> str:
        return "DecoClient(base_url=%r, logged_in=%r)" % (self._base, self.logged_in)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.logout()
        return False

    # -- session state -------------------------------------------------------

    def _clear_session(self) -> None:
        self._stok = None
        self._cookie = None
        self._seq = None
        self._sign_n = None
        self._sign_e = None
        self._aes_key = None
        self._aes_iv = None

    # -- transport -----------------------------------------------------------

    def _url(self, stok: str, path: str, form: str) -> str:
        return "%s/cgi-bin/luci/;stok=%s/%s?form=%s" % (
            self._base, stok or "", path, urllib.parse.quote(form, safe="_"))

    def _post(self, stok: str, path: str, form: str, body: str, cookie: bool):
        """POST once. Returns (status, headers, body_bytes); handles redirects.

        HTTP errors (4xx/5xx) are returned as a status, never raised. Network
        problems raise DecoConnectionError.
        """
        data = body.encode("utf-8")
        for _ in range(4):
            url = self._url(stok, path, form)
            headers = {
                "Content-Type": "application/json",  # yes, even for the form body
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "decodash/1.0",
            }
            if cookie and self._cookie:
                headers["Cookie"] = "sysauth=%s" % self._cookie
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            try:
                resp = self._opener.open(req, timeout=self.timeout)
                try:
                    status = resp.status if hasattr(resp, "status") else resp.getcode()
                    return status, resp.headers, resp.read()
                finally:
                    resp.close()
            except urllib.error.HTTPError as err:
                try:
                    payload = err.read()
                except Exception:
                    payload = b""
                finally:
                    try:
                        err.close()
                    except Exception:
                        pass
                if err.code in (301, 302, 303, 307, 308):
                    location = err.headers.get("Location") if err.headers else None
                    self._follow_redirect(url, location)
                    continue
                return err.code, err.headers, payload
            except (socket.timeout, TimeoutError) as err:
                raise DecoConnectionError(self._timeout_message()) from err
            except ssl.SSLError as err:
                raise DecoConnectionError(self._tls_message()) from err
            except urllib.error.URLError as err:
                if isinstance(err.reason, (socket.timeout, TimeoutError)):
                    raise DecoConnectionError(self._timeout_message()) from err
                if isinstance(err.reason, ssl.SSLError):
                    raise DecoConnectionError(self._tls_message()) from err
                raise DecoConnectionError(self._unreachable_message()) from err
            except (http.client.HTTPException, OSError, ValueError) as err:
                raise DecoConnectionError(self._unreachable_message()) from err
        raise DecoConnectionError("The Deco kept redirecting us, so we stopped trying.")

    def _follow_redirect(self, current_url: str, location: str | None) -> None:
        if not location:
            raise DecoConnectionError("The Deco sent a redirect without saying where to go.")
        target = urllib.parse.urlparse(urllib.parse.urljoin(current_url, location))
        current = urllib.parse.urlparse(current_url)
        same_host = (target.hostname or "").lower() == (current.hostname or "").lower()
        if not same_host or target.scheme not in ("http", "https"):
            raise DecoConnectionError(
                "The Deco tried to send us to a different address. For safety this tool "
                "only talks to the Deco address you typed."
            )
        if current.scheme == "https" and target.scheme == "http":
            raise DecoConnectionError(
                "The Deco tried to switch from a secure (https) to an insecure connection, "
                "so we stopped."
            )
        try:
            target_port = target.port
        except ValueError:
            raise DecoConnectionError("The Deco sent a redirect we could not follow.") from None
        new_base = "%s://%s" % (target.scheme, _netloc(target.hostname, target_port))
        if new_base == self._base:
            raise DecoConnectionError("The Deco kept redirecting us, so we stopped trying.")
        self._base = new_base

    def _timeout_message(self) -> str:
        return (
            "The Deco at %s didn't answer within %g seconds. Check that this computer is "
            "connected to your Deco Wi-Fi (or plugged into a Deco) and try again."
            % (self.host, self.timeout)
        )

    def _tls_message(self) -> str:
        return (
            "The secure (https) connection to the Deco at %s failed. If you typed a name "
            "instead of an IP address, try the IP address (like 192.168.68.1)." % self.host
        )

    def _unreachable_message(self) -> str:
        return (
            "Couldn't reach the Deco at %s. Check that this computer is on your Deco "
            "network and that the address is right. The Deco app shows it when you tap "
            "your main Deco (it is often 192.168.68.1)." % self.host
        )

    @staticmethod
    def _parse_json(raw: bytes):
        try:
            return _loads(raw.decode("utf-8", errors="replace"))
        except (ValueError, RecursionError):
            return None

    def _store_cookie(self, headers) -> None:
        if headers is None:
            return
        try:
            values = headers.get_all("Set-Cookie") or []
        except AttributeError:
            values = [headers.get("Set-Cookie")] if headers.get("Set-Cookie") else []
        for value in values:
            match = _COOKIE_RE.search(value or "")
            if match:
                self._cookie = match.group(1)
                return

    # -- encryption ------------------------------------------------------------

    def _encode_payload(self, payload: dict) -> str:
        operation = payload.get("operation") if isinstance(payload, dict) else None
        if operation not in ALLOWED_OPERATIONS:
            raise DecoError(
                "Blocked: this tool is read-only and never sends %r to the Deco." % (operation,)
            )
        text = json.dumps(payload, separators=(",", ":"))
        enc = crypto.aes_cbc_encrypt(
            self._aes_key.encode("ascii"), self._aes_iv.encode("ascii"), text.encode("utf-8"))
        data = base64.b64encode(enc).decode("ascii")
        h = _md5_hex(self._username + self._password)
        sign_text = "k=%s&i=%s&h=%s&s=%d" % (self._aes_key, self._aes_iv, h, self._seq + len(data))
        sign = crypto.rsa_encrypt_chunked(self._sign_n, self._sign_e, sign_text.encode("utf-8"))
        return "sign=%s&data=%s" % (sign, urllib.parse.quote_plus(data))

    def _decrypt(self, value):
        if isinstance(value, dict):
            return value
        if not isinstance(value, str) or not value:
            raise _SessionExpired("empty answer")
        try:
            raw = base64.b64decode(value)
            plain = crypto.aes_cbc_decrypt(
                self._aes_key.encode("ascii"), self._aes_iv.encode("ascii"), raw)
            data = _loads(plain.decode("utf-8", errors="replace"))
        except (ValueError, TypeError, RecursionError) as err:
            raise DecoError("The Deco sent an answer we could not decrypt.") from err
        if not isinstance(data, dict):
            raise DecoError("The Deco sent an answer in an unexpected format.")
        return data

    # -- login -----------------------------------------------------------------

    def _read_public_key(self, form: str):
        status, headers, raw = self._post("", "login", form, json.dumps({"operation": "read"}), False)
        if form == "keys" and status == 401:
            raise DecoUnsupportedFirmware(
                "This Deco uses an older login method that this tool can't speak yet (its "
                "firmware answered 'HTTP 401' to the first login step). The tests that run on "
                "this computer (speed, latency, DNS and Wi-Fi link) still work."
            )
        if status == 403:
            raise DecoAuthError(self._forbidden_message())
        if status != 200:
            raise DecoError(
                "The address %s answered, but not like a Deco does (HTTP %s). Check that it "
                "is your main Deco's IP address." % (self.host, status)
            )
        data = self._parse_json(raw)
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, dict):
            raise DecoError(
                "The address %s answered, but it doesn't look like a TP-Link Deco." % self.host
            )
        return result

    @staticmethod
    def _parse_key(value):
        bad = DecoError("The Deco sent a login key we could not read.")
        if not isinstance(value, (list, tuple)) or len(value) < 2:
            raise bad
        try:
            n = int(str(value[0]), 16)
            e = int(str(value[1]), 16)
        except (TypeError, ValueError):
            raise bad from None
        # PKCS#1 v1.5 needs 11 bytes of overhead, so the key must be longer than that.
        if n <= 0 or e <= 0 or crypto.byte_len(n) <= crypto.PKCS1_V15_OVERHEAD:
            raise bad
        return n, e

    @staticmethod
    def _forbidden_message() -> str:
        return (
            "The Deco refused the login (HTTP 403). This usually means the owner account is "
            "already logged in somewhere else, most often the Deco app on a phone. A Deco only "
            "allows one owner session at a time. Close the Deco app completely, wait a minute, "
            "then try again."
        )

    def login(self) -> None:
        """Log in as the owner. Raises DecoAuthError, DecoUnsupportedFirmware,
        DecoConnectionError or DecoError."""
        with self._lock:
            self._clear_session()
            if not self._password:
                raise DecoAuthError("Type your Deco owner password first.")
            # Checked without encoding, so no UnicodeEncodeError (which would carry
            # the whole password in its .object) is ever created or chained.
            if _has_surrogates(self._password) or _has_surrogates(self._username):
                raise DecoAuthError(
                    "Your password has a character in it that can't be sent to the Deco. "
                    "Type it again by hand instead of pasting it."
                )
            keys = self._read_public_key("keys")
            pw_n, pw_e = self._parse_key(keys.get("password"))
            auth = self._read_public_key("auth")
            self._sign_n, self._sign_e = self._parse_key(auth.get("key"))
            try:
                self._seq = int(auth.get("seq"))
            except (TypeError, ValueError):
                raise DecoError("The Deco sent a login sequence number we could not read.") from None
            self._aes_key = crypto.random_16_digit()
            self._aes_iv = crypto.random_16_digit()

            encrypted_password = crypto.rsa_encrypt_chunked(
                pw_n, pw_e, self._password.encode("utf-8"))
            body = self._encode_payload(
                {"params": {"password": encrypted_password}, "operation": "login"})
            status, headers, raw = self._post("", "login", "login", body, False)
            if status == 403:
                self._clear_session()
                raise DecoAuthError(self._forbidden_message())
            if status == 401:
                self._clear_session()
                raise DecoAuthError(
                    "The Deco rejected the login (HTTP 401). Use the owner password: the "
                    "TP-Link ID password you use in the Deco app."
                )
            if status != 200:
                self._clear_session()
                raise DecoError("The Deco answered the login with an error (HTTP %s)." % status)

            outer = self._parse_json(raw)
            if not isinstance(outer, dict):
                self._clear_session()
                raise DecoError("The Deco sent a login answer we could not read.")
            try:
                data = self._decrypt(outer["data"]) if "data" in outer else outer
            except DecoError:
                self._clear_session()
                raise DecoError("The Deco sent a login answer we could not read.") from None
            code = _error_code(data)
            result = data.get("result") if isinstance(data.get("result"), dict) else {}
            if code not in (0, None):
                self._clear_session()
                if code == _WRONG_PASSWORD_CODE:
                    raise DecoAuthError(self._wrong_password_message(result))
                raise DecoAuthError(
                    "The Deco refused the login (error code %s). Check the owner password and "
                    "try again in a minute." % (code,)
                )
            stok = result.get("stok")
            if not isinstance(stok, str) or not stok:
                self._clear_session()
                raise DecoError("The Deco accepted the login but didn't give us a session.")
            self._store_cookie(headers)
            if not self._cookie:
                self._clear_session()
                raise DecoError("The Deco accepted the login but didn't send a session cookie.")
            self._stok = stok

    @staticmethod
    def _wrong_password_message(result: dict) -> str:
        left = result.get("attemptsAllowed") if isinstance(result, dict) else None
        try:
            left = int(left)
        except (TypeError, ValueError):
            left = None
        base = (
            "That password didn't work. Use the owner password: the TP-Link ID password "
            "you use in the Deco app (manager accounts can't log in here)."
        )
        if left is None:
            return base
        if left <= 0:
            return (
                "Too many wrong passwords, so the Deco has paused logins for a while "
                "(0 tries left). Wait a bit, then try again with the owner password."
            )
        return "%s You have %d %s left before the Deco blocks logins for a while." % (
            base, left, "try" if left == 1 else "tries")

    # -- authenticated calls ---------------------------------------------------

    def _call_once(self, path: str, form: str, payload: dict):
        body = self._encode_payload(payload)
        status, headers, raw = self._post(self._stok, path, form, body, True)
        if status in (401, 403):
            raise _SessionExpired("HTTP %s" % status)
        if status != 200:
            raise DecoError("The Deco answered with an error (HTTP %s)." % status)
        self._store_cookie(headers)
        outer = self._parse_json(raw)
        if not isinstance(outer, dict):
            raise DecoError("The Deco sent an answer we could not read.")
        if "data" in outer:
            data = self._decrypt(outer.get("data"))
        else:
            data = outer
        code = _error_code(data)
        if code in _SESSION_EXPIRED_CODES or code == "timeout":
            raise _SessionExpired("error_code %s" % (code,))
        if code not in (0, None, ""):
            raise DecoError("The Deco answered with error code %s." % (code,))
        result = data.get("result")
        return result if result is not None else {}

    def _call(self, path: str, form: str, payload: dict):
        with self._lock:
            if not self.logged_in:
                self.login()
            try:
                return self._call_once(path, form, payload)
            except _SessionExpired:
                pass
            # The session ended (timeout, or someone else logged in): log in
            # again once and retry once. Login errors propagate as they are.
            self.login()
            try:
                return self._call_once(path, form, payload)
            except _SessionExpired:
                self._clear_session()
                raise DecoError(
                    "The Deco keeps ending our session. Make sure nobody else (like the Deco "
                    "app) is logged in as the owner at the same time."
                ) from None

    def _read(self, path: str, form: str, params: dict | None = None):
        payload = {"operation": "read"}
        if params:
            payload["params"] = params
        return self._call(path, form, payload)

    # -- public API --------------------------------------------------------------

    def fetch_all(self) -> dict:
        """Read every endpoint and return DecoData (see SPEC.md).

        Logs in first if needed (login errors are raised). After that, each
        endpoint is read on its own: one failing does not stop the others, and
        its message goes into ``errors[<key>]``. Two exceptions, so we don't
        hammer a Deco that is clearly unhappy: if we end up logged out (logging
        in again failed), or two calls in a row can't reach the Deco, the
        remaining calls are skipped (and say so in ``errors``).
        """
        with self._lock:
            if not self.logged_in:
                self.login()
            state = _FetchState()
            raw = {key: None for key, _p, _f, _x, _l in ENDPOINTS}
            errors = {}

            for key, path, form, params, label in ENDPOINTS:
                if key == "ipv6":
                    continue  # optional; read last
                ok, value, message = self._attempt(state, lambda: self._read(path, form, params))
                if ok:
                    raw[key] = _unwrap(value, _UNWRAP.get(key))
                else:
                    errors[key] = _error_text(label, message)

            # Which Deco is each client attached to? Ask each node on its own,
            # passing its MAC exactly as device_list gave it.
            per_node_raw = {}
            node_of_client = {}
            failed_nodes = []
            device_items = [i for i in _as_list(raw["device_list"], "device_list") if isinstance(i, dict)]
            for item in device_items:
                mac_as_given = item.get("mac")
                node_mac = normalize_mac(mac_as_given)
                if not node_mac or not isinstance(mac_as_given, str):
                    continue
                ok, value, _message = self._attempt(
                    state,
                    lambda: self._read("admin/client", "client_list", {"device_mac": mac_as_given}),
                )
                if not ok:
                    failed_nodes.append(_node_label(item))
                    continue
                items = _as_list(_unwrap(value, "client_list"), "client_list")
                per_node_raw[mac_as_given] = items
                for c in items:
                    if isinstance(c, dict):
                        cmac = normalize_mac(c.get("mac"))
                        if cmac:
                            node_of_client[cmac] = node_mac
            if failed_nodes:
                errors[PER_NODE_KEY] = (
                    "Couldn't tell which Deco some devices are connected to (no answer for: %s)."
                    % ", ".join(failed_nodes)
                )

            # Optional endpoint: errors are ignored on purpose.
            ok, value, _message = self._attempt(
                state, lambda: self._read("admin/network", "wan_ipv6", None))
            raw["ipv6"] = value if ok else None

            # Clients. If the main list failed but per-node lists worked, use those.
            client_items = raw["client_list"]
            if not isinstance(client_items, list) and per_node_raw:
                merged = {}
                for items in per_node_raw.values():
                    for c in items:
                        if isinstance(c, dict):
                            merged.setdefault(normalize_mac(c.get("mac")) or str(id(c)), c)
                client_items = list(merged.values())
            clients = normalize_clients(client_items if isinstance(client_items, list) else [])
            known_nodes = {normalize_mac(i.get("mac")) for i in device_items} - {None}
            for c in clients:
                # The per-node answers win. Otherwise use access_host / device_mac from
                # the client itself (SPEC), but only if it is one of our Decos.
                mapped = node_of_client.get(c.get("mac"))
                if mapped is None:
                    own = c.get("node_mac")
                    mapped = own if own and (not known_nodes or own in known_nodes) else None
                c["node_mac"] = mapped

            nodes = normalize_nodes(device_items, clients)
            names = {n["mac"]: n["name"] for n in nodes if n.get("mac")}
            for c in clients:
                c["node_name"] = names.get(c["node_mac"]) if c.get("node_mac") else None

            raw_out = dict(raw)
            raw_out[PER_NODE_KEY] = per_node_raw or None
            return {
                "fetched_at": _now_iso(),
                "nodes": nodes,
                "clients": clients,
                "wifi": normalize_wlan(raw["wlan"]),
                "wan": normalize_wan(raw["wan_ipv4"], raw["ipv6"]),
                "performance": normalize_performance(raw["performance"]),
                "errors": errors,
                "raw": redact(raw_out),
                # optional extra
                "base_url": self._base,
            }

    def _attempt(self, state: "_FetchState", func):
        """Run one read. Returns (ok, value, error_message)."""
        if state.abort_reason is not None:
            return False, None, "Skipped: " + state.abort_reason
        try:
            value = func()
        except DecoError as err:
            if isinstance(err, DecoConnectionError):
                state.connection_failures += 1
            else:
                state.connection_failures = 0
            if not self.logged_in:
                # Logging in again failed (or the Deco keeps ending our session).
                # Stop here instead of retrying the login for every endpoint,
                # which could use up the owner's password tries.
                state.abort_reason = str(err)
            elif state.connection_failures >= 2:
                state.abort_reason = "the Deco stopped answering."
            return False, None, str(err)
        except Exception as err:  # defensive: one odd answer must not break the rest
            state.connection_failures = 0
            return False, None, "unexpected problem (%s)." % type(err).__name__
        state.connection_failures = 0
        return True, value, None

    def logout(self) -> None:
        """Best-effort logout. Never raises."""
        try:
            with self._lock:
                if self.logged_in:
                    try:
                        self._call_once("admin/system", "logout", {"operation": "logout"})
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            try:
                self._clear_session()
            except Exception:
                pass


class _FetchState:
    def __init__(self) -> None:
        self.abort_reason = None
        self.connection_failures = 0


_UNWRAP = {"device_list": "device_list", "client_list": "client_list"}


def _unwrap(result, inner):
    if inner and isinstance(result, dict) and inner in result:
        return result[inner]
    return result


def _error_text(label: str, message: str) -> str:
    if message.startswith("Skipped"):
        return message
    return "Couldn't read %s: %s" % (label, message)


def _node_label(item: dict) -> str:
    name = decode_name(item.get("custom_nickname")) or _pretty_nickname(item.get("nickname"))
    return name or (normalize_mac(item.get("mac")) or "unknown Deco")


# ---------------------------------------------------------------------------
# Small value helpers
# ---------------------------------------------------------------------------

_MAC_HEX_RE = re.compile(r"[0-9A-Fa-f]")


def normalize_mac(value) -> str | None:
    """'f0-09-0d-fa-29-84' / 'F0:09:...' / 'f0090dfa2984' -> 'F0:09:0D:FA:29:84'.

    Returns None for anything that is not a real 48-bit MAC (including all zeros).
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    hexdigits = re.sub(r"[\s:\-\.]", "", text)
    if len(hexdigits) != 12 or not re.fullmatch(r"[0-9A-Fa-f]{12}", hexdigits):
        return None
    hexdigits = hexdigits.upper()
    if hexdigits == "000000000000":
        return None
    return ":".join(hexdigits[i: i + 2] for i in range(0, 12, 2))


def _looks_like_text(text: str) -> bool:
    if not text or not text.strip():
        return False
    nonspace = 0
    good = 0
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith("C") and ch not in ("\u200d", "\ufe0f"):
            return False  # control / unassigned / private-use characters
        if ch.isspace():
            if ch not in (" ",):
                return False
            continue
        nonspace += 1
        if ch.isalnum() or cat in ("So", "Sk", "Mn", "Mc"):
            good += 1
    return nonspace > 0 and good * 2 >= nonspace


def decode_name(value) -> str:
    """Decode a base64 name from the Deco; keep the raw value if it isn't one.

    A value counts as base64 only if it is canonical base64 and decodes to
    readable UTF-8 text, so plain names such as "Kids" stay as they are.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        return str(value)
    text = value.strip()
    if not text:
        return ""
    if len(text) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
        try:
            raw = base64.b64decode(text, validate=True)
            if base64.b64encode(raw).decode("ascii") == text:
                decoded = raw.decode("utf-8")
                if _looks_like_text(decoded):
                    return decoded.strip()
        except (ValueError, UnicodeDecodeError):
            pass
    return text


def _pretty_nickname(value) -> str:
    """Deco preset nicknames look like 'living_room'; show them as 'Living Room'.

    ``nickname`` is plain text in both reference clients (only
    ``custom_nickname`` is base64), so it is not base64-decoded here.
    """
    text = value.strip() if isinstance(value, str) else ""
    if text and re.fullmatch(r"[a-z0-9_]+", text):
        return " ".join(w.capitalize() for w in text.split("_") if w)
    return text


_BAND_ALIASES = {
    "band2_4": "band2_4", "band2_4g": "band2_4", "band2g": "band2_4", "band24": "band2_4",
    "2_4g": "band2_4", "2.4g": "band2_4", "2g": "band2_4", "2.4ghz": "band2_4", "2_4": "band2_4",
    "band5": "band5", "band5_1": "band5", "band5_2": "band5", "band5g": "band5",
    "band5g_1": "band5", "band5g_2": "band5", "5g": "band5", "5ghz": "band5", "5g_1": "band5", "5g_2": "band5",
    "band6": "band6", "band6_1": "band6", "band6_2": "band6", "band6g": "band6", "6g": "band6", "6ghz": "band6",
}


def normalize_band(value) -> str | None:
    """'band5_1', 'band5_2', 'band5' -> 'band5'; 'band2_4' -> 'band2_4'; etc."""
    if not isinstance(value, str):
        return None
    key = value.strip().lower().replace("-", "_")
    return _BAND_ALIASES.get(key)


_TRUE_WORDS = frozenset({"1", "true", "on", "enable", "enabled", "yes"})
_FALSE_WORDS = frozenset({"0", "false", "off", "disable", "disabled", "no"})


def parse_enable(value) -> bool | None:
    """Enable flags come as True, 1, "1", "on", "enable", "enabled", "true" (and the
    matching off words). Anything else gives None."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
        return None
    if isinstance(value, str):
        word = value.strip().lower()
        if word in _TRUE_WORDS:
            return True
        if word in _FALSE_WORDS:
            return False
    return None


def _num(value) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        f = float(value)
    elif isinstance(value, str):
        try:
            f = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    if f != f or f in (float("inf"), float("-inf")):
        return None
    return f


def _int(value) -> int | None:
    f = _num(value)
    if f is None:
        return None
    return int(round(f))


def _str(value) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _ip(value, allow_zero: bool = False) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip.is_unspecified and not allow_zero:
        return None
    return str(ip)


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _band_values(mapping, convert) -> dict:
    """Per-band values with band keys normalised; the first value wins."""
    out = {b: None for b in BANDS}
    if not isinstance(mapping, dict):
        return out
    # Prefer exact keys (band5) over numbered ones (band5_1, band5_2).
    items = sorted(mapping.items(), key=lambda kv: (0 if kv[0] in BANDS else 1, str(kv[0])))
    for key, raw in items:
        band = normalize_band(key)
        if band is None or out[band] is not None:
            continue
        out[band] = convert(raw)
    return out


# ---------------------------------------------------------------------------
# Normalisers
# ---------------------------------------------------------------------------


def _as_list(value, inner_key: str) -> list:
    if isinstance(value, dict):
        value = value.get(inner_key)
    return value if isinstance(value, list) else []


def _connection_types(value) -> list:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    return [str(v).strip().lower() for v in value if isinstance(v, (str, int))]


def _normalize_node(item: dict, is_main: bool) -> dict:
    mac = normalize_mac(item.get("mac"))
    name = decode_name(item.get("custom_nickname")) or _pretty_nickname(item.get("nickname"))
    if not name:
        name = mac or "Deco"

    conn = _connection_types(item.get("connection_type"))
    wired = any(c in ("wired", "ethernet", "eth", "lan") or ("wire" in c and "wireless" not in c)
                for c in conn)
    conn_bands = []
    for c in conn:
        band = normalize_band(c)
        if band and band not in conn_bands:
            conn_bands.append(band)

    def dbm(v):
        f = _int(v)
        return f if f is not None and f < 0 else None

    def bars(v):
        return _int(v)

    def rate(v):
        f = _num(v)
        return f if f is not None and f > 0 else None

    signal_dbm = _band_values(item.get("signal_strength"), dbm)
    signal_bars = _band_values(item.get("signal_level"), bars)
    for band in BANDS:
        b = signal_bars[band]
        if b is not None and (b < 0 or (b == 0 and (is_main or band not in conn_bands))):
            signal_bars[band] = None
    if is_main:
        signal_dbm = {b: None for b in BANDS}
        signal_bars = {b: None for b in BANDS}

    online = None
    group = item.get("group_status")
    if isinstance(group, str):
        online = group.strip().lower() == "connected"
    elif isinstance(group, bool):
        online = group

    inet = item.get("inet_status")
    internet_online = None
    if isinstance(inet, str):
        internet_online = inet.strip().lower() in ("online", "connected", "up")
    elif isinstance(inet, (bool, int)) and inet is not None:
        internet_online = bool(inet)

    if is_main:
        backhaul = "n/a"
        backhaul_bands = []
        parent = None
    else:
        parent = normalize_mac(item.get("previous"))
        signal_bands = [b for b in BANDS if signal_dbm[b] is not None or signal_bars[b] is not None]
        if wired:
            backhaul = "wired"
            backhaul_bands = sorted(conn_bands, key=lambda b: _BAND_ORDER[b])
        elif conn_bands or signal_bands:
            backhaul = "wireless"
            seen = list(conn_bands)
            for b in signal_bands:
                if b not in seen:
                    seen.append(b)
            backhaul_bands = sorted(seen, key=lambda b: _BAND_ORDER[b])
        else:
            backhaul = "unknown"
            backhaul_bands = []

    speed = item.get("backhual_speed", item.get("backhaul_speed"))
    max_speed = item.get("backhual_max_speed", item.get("backhaul_max_speed"))
    speed = _num(speed)
    max_speed = _num(max_speed)

    wired_ports = _int(item.get("port_count"))
    if wired_ports is not None and wired_ports < 0:
        wired_ports = None

    bssids = {
        "band2_4": normalize_mac(item.get("bssid_2g")),
        "band5": normalize_mac(item.get("bssid_5g")) or normalize_mac(item.get("bssid_5g_1")),
        "band6": normalize_mac(item.get("bssid_6g")),
    }

    return {
        "mac": mac,
        "name": name,
        "model": _str(item.get("device_model")),
        "hw_version": _str(item.get("hardware_ver")),
        "fw_version": _str(item.get("software_ver")),
        "ip": _ip(item.get("device_ip")),
        "role": "main" if is_main else "satellite",
        "online": online,
        "internet_online": internet_online,
        "parent_mac": parent,
        "backhaul": backhaul,
        "backhaul_bands": backhaul_bands,
        "signal_dbm": signal_dbm,
        "signal_bars": signal_bars,
        "rx_rate_mbps": {b: None for b in BANDS} if is_main else _band_values(item.get("rx_rate_list"), rate),
        "tx_rate_mbps": {b: None for b in BANDS} if is_main else _band_values(item.get("tx_rate_list"), rate),
        "backhaul_speed_mbps": speed if speed is not None and speed > 0 else None,
        "backhaul_max_mbps": max_speed if max_speed is not None and max_speed > 0 else None,
        "wired_ports": wired_ports,
        "client_count": 0,
        # optional extras
        "bssids": bssids,
    }


def normalize_nodes(device_list: list, clients: list | None = None) -> list:
    """Turn device_list items into Node dicts (main node first)."""
    items = [i for i in _as_list(device_list, "device_list") if isinstance(i, dict)]
    main_flags = []
    for item in items:
        role = item.get("role")
        role = role.strip().lower() if isinstance(role, str) else ""
        main_flags.append(role in ("master", "main", "root", "controller", "gateway"))
    if items and not any(main_flags):
        roles = [str(i.get("role") or "").strip().lower() for i in items]
        if len(items) == 1 and roles[0] not in ("slave", "satellite"):
            main_flags = [True]
        else:
            no_parent = [idx for idx, i in enumerate(items)
                         if not normalize_mac(i.get("previous")) and roles[idx] not in ("slave", "satellite")]
            if len(no_parent) == 1:
                main_flags[no_parent[0]] = True

    nodes = []
    for item, is_main in zip(items, main_flags):
        try:
            nodes.append(_normalize_node(item, is_main))
        except Exception:  # pragma: no cover - extremely odd input
            continue

    counts = {}
    for c in clients if isinstance(clients, list) else []:
        node_mac = c.get("node_mac") if isinstance(c, dict) else None
        if isinstance(node_mac, str) and node_mac and c.get("online"):
            counts[node_mac] = counts.get(node_mac, 0) + 1
    for n in nodes:
        n["client_count"] = counts.get(n["mac"], 0) if n["mac"] else 0

    nodes.sort(key=lambda n: 0 if n["role"] == "main" else 1)  # stable: keeps order otherwise
    return nodes


def normalize_clients(client_list: list) -> list:
    """Turn client_list items into Client dicts."""
    out = []
    for item in _as_list(client_list, "client_list"):
        if not isinstance(item, dict):
            continue
        raw_mac = item.get("mac")
        mac = normalize_mac(raw_mac) or (raw_mac.strip() if isinstance(raw_mac, str) else "")
        name = decode_name(item.get("name")) or decode_name(item.get("client_name")) or mac or "Unknown device"

        conn = item.get("connection_type")
        wire_type = item.get("wire_type")
        band = "unknown"
        conn_l = conn.strip().lower() if isinstance(conn, str) else ""
        wire_l = wire_type.strip().lower() if isinstance(wire_type, str) else ""
        if wire_l == "wired" or conn_l in ("wired", "ethernet", "lan"):
            band = "wired"
        else:
            band = normalize_band(conn_l) or "unknown"

        online = item.get("online")
        online_flag = parse_enable(online) if online is not None else True
        if online_flag is None:
            online_flag = bool(online)

        node_mac = normalize_mac(item.get("access_host")) or normalize_mac(item.get("device_mac"))

        def kbps(v):
            f = _num(v)
            return round(f * 8 / 1000.0, 3) if f is not None and f >= 0 else 0.0

        interface = item.get("interface")
        out.append({
            "mac": mac,
            "name": name,
            "ip": _ip(item.get("ip")),
            "online": bool(online_flag),
            "band": band,
            "interface": interface.strip() if isinstance(interface, str) and interface.strip() else None,
            "node_mac": node_mac,
            "down_kbps": kbps(item.get("down_speed")),
            "up_kbps": kbps(item.get("up_speed")),
            # optional extras
            "node_name": None,
        })
    return out


def _width_mhz(width) -> int | None:
    if isinstance(width, (int, float)) and not isinstance(width, bool):
        f = _num(width)  # None for NaN / inf
        return int(f) if f is not None and f > 0 else None
    if not isinstance(width, str):
        return None
    match = re.search(r"(\d+)", width)
    if not match:
        return None
    value = int(match.group(1))
    return value if value > 0 else None


def _band_cfg(section) -> dict | None:
    if not isinstance(section, dict):
        return None
    host = _dict(section.get("host"))
    channel = _int(host.get("channel"))
    width = host.get("channel_width")
    width_str = _str(width)
    backhaul_channel = _int(_dict(section.get("backhaul")).get("channel"))
    hidden = host.get("enable_hide_ssid", host.get("hide_ssid"))
    ssid = host.get("ssid")
    return {
        "enabled": parse_enable(host.get("enable")),
        "channel": channel if channel and channel > 0 else None,
        "channel_width": width_str,
        "width_mhz": _width_mhz(width),
        "mode": _str(host.get("mode")),
        "backhaul_channel": backhaul_channel if backhaul_channel and backhaul_channel > 0 else None,
        "hidden": parse_enable(hidden) if hidden is not None else None,
        # optional extra (the network name is not a secret)
        "ssid": decode_name(ssid) if isinstance(ssid, str) and ssid else None,
    }


def _collect_flags(node, out: list, depth: int = 0) -> None:
    """Collect every enable-like flag below ``node``."""
    if depth > 6:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            k = str(key).lower()
            if k in ("enable", "enabled", "status") or k.endswith("_enable"):
                flag = parse_enable(value)
                if flag is not None:
                    out.append(flag)
            elif isinstance(value, (dict, list)):
                _collect_flags(value, out, depth + 1)
    elif isinstance(node, list):
        for value in node:
            _collect_flags(value, out, depth + 1)


def _find_mlo_flags(node, out: list, depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            k = str(key).lower()
            if "mlo" in k and "support" not in k and "capab" not in k:
                if isinstance(value, (dict, list)):
                    _collect_flags(value, out)
                else:
                    flag = parse_enable(value)
                    if flag is not None:
                        out.append(flag)
            elif isinstance(value, (dict, list)):
                _find_mlo_flags(value, out, depth + 1)
    elif isinstance(node, list):
        for value in node:
            _find_mlo_flags(value, out, depth + 1)


def normalize_wlan(wlan: dict) -> dict:
    """Turn the wlan answer into WifiConfig (never includes passwords)."""
    wlan = _dict(wlan)
    bands = {b: None for b in BANDS}
    groups = {"band2_4": [], "band5": [], "band6": []}
    for key in sorted(wlan.keys(), key=str):
        band = normalize_band(key)
        if band and isinstance(wlan[key], dict):
            groups[band].append(key)
    for band, keys in groups.items():
        # exact key first, then _1, _2 ...
        keys.sort(key=lambda k: (0 if k == band else 1, k))
        for idx, key in enumerate(keys):
            name = band if idx == 0 else "%s_%d" % (band, idx + 1)
            bands[name] = _band_cfg(wlan[key])

    guest_flags = []
    ssids = []
    for band, keys in groups.items():
        for key in keys:
            section = _dict(wlan[key])
            guest = section.get("guest")
            if isinstance(guest, dict) and "enable" in guest:
                flag = parse_enable(guest.get("enable"))
                if flag is not None:
                    guest_flags.append(flag)
            host = _dict(section.get("host"))
            ssid = host.get("ssid")
            if isinstance(ssid, str) and ssid and parse_enable(host.get("enable")) is not False:
                ssids.append(decode_name(ssid))
    iot_flags = []
    for key, value in wlan.items():
        if "iot" in str(key).lower():
            if isinstance(value, (dict, list)):
                _collect_flags(value, iot_flags)
            else:
                flag = parse_enable(value)
                if flag is not None:
                    iot_flags.append(flag)
    mlo_flags = []
    _find_mlo_flags(wlan, mlo_flags)

    return {
        "bands": bands,
        "guest_enabled": any(guest_flags) if guest_flags else None,
        "iot_enabled": any(iot_flags) if iot_flags else None,
        "mlo_enabled": any(mlo_flags) if mlo_flags else None,
        "same_ssid_all_bands": (len(set(ssids)) == 1) if len(ssids) >= 2 else None,
    }


_PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def _nat_flags(wan_ip: str | None):
    if not wan_ip:
        return None, None
    try:
        ip = ipaddress.ip_address(wan_ip)
    except ValueError:
        return None, None
    if ip.version != 4:
        return False, False
    if any(ip in net for net in _PRIVATE_NETS):
        return True, False
    if ip in _CGNAT_NET:
        return False, True
    return False, False


def _ipv6_enabled(ipv6) -> bool | None:
    if not isinstance(ipv6, dict) or not ipv6:
        return None
    candidates = [ipv6]
    for key in ("wan", "lan"):
        if isinstance(ipv6.get(key), dict):
            candidates.append(ipv6[key])
    for section in candidates:
        for key in ("enable", "ipv6_enable", "enable_ipv6"):
            if key in section:
                flag = parse_enable(section.get(key))
                if flag is not None:
                    return flag
    wan = _dict(ipv6.get("wan"))
    dial = wan.get("dial_type", ipv6.get("dial_type"))
    if isinstance(dial, str) and dial.strip().lower() in ("none", "disable", "disabled", "off"):
        return False
    info = _dict(wan.get("ip_info")) or _dict(ipv6.get("ip_info"))
    for key in ("ip", "ipv6", "addr", "address"):
        value = info.get(key)
        if isinstance(value, str):
            try:
                ip = ipaddress.ip_address(value.split("/")[0].strip())
            except ValueError:
                continue
            if ip.version == 6 and not ip.is_link_local and not ip.is_unspecified:
                return True
    return None


def normalize_wan(wan_ipv4: dict | None, ipv6: dict | None = None) -> dict:
    """Turn wan_ipv4 (+ optional wan_ipv6) into WanInfo."""
    data = _dict(wan_ipv4)
    wan = _dict(data.get("wan"))
    info = _dict(wan.get("ip_info")) or _dict(wan.get("mobile_cpe"))
    lan = _dict(_dict(data.get("lan")).get("ip_info"))

    wan_ip = _ip(info.get("ip"))
    dns = []
    for key in ("dns1", "dns2", "dns3", "pri_dns", "snd_dns"):
        value = _ip(info.get(key))
        if value and value not in dns:
            dns.append(value)
    if isinstance(info.get("dns"), list):
        for value in info["dns"]:
            value = _ip(value)
            if value and value not in dns:
                dns.append(value)
    auto_dns = wan.get("enable_auto_dns", info.get("enable_auto_dns"))
    double_nat, cgnat = _nat_flags(wan_ip)
    return {
        "wan_ip": wan_ip,
        "wan_mask": _ip(info.get("mask")),
        "gateway": _ip(info.get("gateway")),
        "dial_type": _str(wan.get("dial_type")),
        "dns": dns,
        "auto_dns": parse_enable(auto_dns) if auto_dns is not None else None,
        "lan_ip": _ip(lan.get("ip")),
        "lan_mask": _ip(lan.get("mask")),
        "double_nat": double_nat,
        "cgnat": cgnat,
        "ipv6_enabled": _ipv6_enabled(ipv6),
    }


def normalize_performance(perf: dict | None) -> dict:
    """cpu_usage / mem_usage (0..1 fractions) -> percentages 0..100."""
    data = _dict(perf)

    def pct(value):
        f = _num(value)
        if f is None or f < 0:
            return None
        if f <= 1.0:
            f *= 100.0
        if f > 100.0:
            return None
        return round(f, 1)

    return {"cpu_pct": pct(data.get("cpu_usage")), "mem_pct": pct(data.get("mem_usage"))}


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

_SECRET_PARTS = ("password", "passwd", "psk", "secret", "token", "stok", "sysauth",
                 "wpa", "passphrase", "pwd", "credential")
_SECRET_EXACT = frozenset({"key", "pin", "pass", "pw"})
# Whole words inside a key name (split on _ - . spaces, camelCase and digits),
# so "wifiKey", "wep_key1", "x-api-key" and "guest_pass" count, but "monkey",
# "keys", "ssid" and "passive_scan" don't.
_SECRET_WORDS = frozenset({"key", "pass", "pin", "pw", "pwd", "psk", "cookie", "apikey", "privkey"})
_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
REDACTED = "***"


def _is_secret_key(key) -> bool:
    if not isinstance(key, str):
        return False
    k = key.lower()
    if k in _SECRET_EXACT or k.endswith("_key") or k.endswith("_pin"):
        return True
    if any(part in k for part in _SECRET_PARTS):
        return True
    return any(word.lower() in _SECRET_WORDS for word in _WORD_RE.findall(key))


def redact(obj):
    """Deep copy of ``obj`` with the value of every secret-looking key set to "***".

    Secret-looking: the lower-case key contains password, passwd, psk, secret,
    token, stok, sysauth, wpa, passphrase, pwd or credential; or it is exactly
    "key" / "pin" / "pass" / "pw"; or it ends with "_key" / "_pin"; or one of
    its words (camelCase, snake_case, kebab-case, digits split off) is key,
    pass, pin, pw, pwd, psk, cookie, apikey or privkey.
    """
    if isinstance(obj, dict):
        return {k: (REDACTED if _is_secret_key(k) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact(v) for v in obj)
    return copy.deepcopy(obj)
