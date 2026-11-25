"""Crypto helpers for the TP-Link Deco local web API.

The Deco protects its local API with two things:

* AES-128-CBC with PKCS#7 padding for request and response bodies. The key
  and IV are random 16-digit decimal numbers that we pick ourselves and send
  (RSA-encrypted) inside every request's ``sign`` field.
* RSA PKCS#1 v1.5 (type 2) public-key encryption for the login password and
  for the ``sign`` field. TP-Link splits long plaintexts into chunks that fit
  in one RSA block and glues the hex ciphertexts together.

Everything here is pure Python standard library. If the optional
``cryptography`` package is installed, it is used for the AES part only, as a
faster path that gives byte-for-byte identical results (padding is always done
by this module, so both paths behave the same, errors included).
"""

from __future__ import annotations

import secrets
import struct

__all__ = [
    "aes_cbc_encrypt",
    "aes_cbc_decrypt",
    "aes_cbc_encrypt_raw",
    "aes_cbc_decrypt_raw",
    "pkcs7_pad",
    "pkcs7_unpad",
    "rsa_encrypt_chunked",
    "rsa_pkcs1_v15_pad",
    "byte_len",
    "random_16_digit",
    "HAVE_FAST_AES",
    "USE_FAST_PATH",
]

BLOCK_SIZE = 16
PKCS1_V15_OVERHEAD = 11  # 0x00 0x02 + at least 8 random bytes + 0x00

# ---------------------------------------------------------------------------
# Optional fast path
# ---------------------------------------------------------------------------

try:  # pragma: no cover - depends on what is installed
    from cryptography.hazmat.backends import default_backend as _default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as _algorithms
    from cryptography.hazmat.primitives.ciphers import modes as _modes

    HAVE_FAST_AES = True
except (KeyboardInterrupt, SystemExit):  # pragma: no cover
    raise
except BaseException:  # pragma: no cover - not installed, or a broken install
    # A broken binary install can raise pyo3's PanicException, which is a
    # BaseException, so catch broadly here and fall back to pure Python.
    HAVE_FAST_AES = False

#: Set to False to force the pure-Python AES code (tests do this).
USE_FAST_PATH = True


def _fast_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    cipher = _Cipher(_algorithms.AES(key), _modes.CBC(iv), backend=_default_backend())
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(data) + ctx.finalize()


# ---------------------------------------------------------------------------
# Pure-Python AES (FIPS-197), table driven
# ---------------------------------------------------------------------------


def _build_tables():
    """Build the S-boxes and the four encryption/decryption T-tables."""
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        # multiply x by the generator 3 in GF(2^8)
        x2 = (x << 1) ^ (0x11B if x & 0x80 else 0)
        x = x2 ^ x
    for i in range(255, 512):
        exp[i] = exp[i - 255]

    def mul(a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return exp[log[a] + log[b]]

    sbox = [0] * 256
    for a in range(256):
        inv = 0 if a == 0 else exp[255 - log[a]]
        s = inv
        r = inv
        for _ in range(4):
            r = ((r << 1) | (r >> 7)) & 0xFF
            s ^= r
        sbox[a] = s ^ 0x63
    inv_sbox = [0] * 256
    for i, s in enumerate(sbox):
        inv_sbox[s] = i

    def ror8(w: int) -> int:
        return ((w >> 8) | (w << 24)) & 0xFFFFFFFF

    te0 = []
    td0 = []
    for i in range(256):
        s = sbox[i]
        te0.append((mul(s, 2) << 24) | (s << 16) | (s << 8) | mul(s, 3))
        si = inv_sbox[i]
        td0.append((mul(si, 14) << 24) | (mul(si, 9) << 16) | (mul(si, 13) << 8) | mul(si, 11))
    te1 = [ror8(w) for w in te0]
    te2 = [ror8(w) for w in te1]
    te3 = [ror8(w) for w in te2]
    td1 = [ror8(w) for w in td0]
    td2 = [ror8(w) for w in td1]
    td3 = [ror8(w) for w in td2]
    return sbox, inv_sbox, (te0, te1, te2, te3), (td0, td1, td2, td3)


_SBOX, _INV_SBOX, _TE, _TD = _build_tables()
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


class _PureAES:
    """One AES key schedule (128, 192 or 256 bit keys)."""

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes long")
        nk = len(key) // 4
        self.rounds = nk + 6
        total = 4 * (self.rounds + 1)
        sb = _SBOX
        w = list(struct.unpack(">%dI" % nk, key))
        for i in range(nk, total):
            t = w[i - 1]
            if i % nk == 0:
                t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
                t = (
                    (sb[t >> 24] << 24)
                    | (sb[(t >> 16) & 0xFF] << 16)
                    | (sb[(t >> 8) & 0xFF] << 8)
                    | sb[t & 0xFF]
                )
                t ^= _RCON[i // nk - 1] << 24
            elif nk > 6 and i % nk == 4:
                t = (
                    (sb[t >> 24] << 24)
                    | (sb[(t >> 16) & 0xFF] << 16)
                    | (sb[(t >> 8) & 0xFF] << 8)
                    | sb[t & 0xFF]
                )
            w.append(w[i - nk] ^ t)
        self.ek = w

        # Decryption key schedule for the "equivalent inverse cipher":
        # round keys in reverse order, InvMixColumns applied to the middle ones.
        td0, td1, td2, td3 = _TD
        dk = []
        for r in range(self.rounds, -1, -1):
            words = w[4 * r: 4 * r + 4]
            if 0 < r < self.rounds:
                words = [
                    td0[sb[x >> 24]]
                    ^ td1[sb[(x >> 16) & 0xFF]]
                    ^ td2[sb[(x >> 8) & 0xFF]]
                    ^ td3[sb[x & 0xFF]]
                    for x in words
                ]
            dk.extend(words)
        self.dk = dk

    def encrypt_words(self, s0: int, s1: int, s2: int, s3: int):
        te0, te1, te2, te3 = _TE
        rk = self.ek
        s0 ^= rk[0]
        s1 ^= rk[1]
        s2 ^= rk[2]
        s3 ^= rk[3]
        k = 4
        for _ in range(self.rounds - 1):
            t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xFF] ^ te2[(s2 >> 8) & 0xFF] ^ te3[s3 & 0xFF] ^ rk[k]
            t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xFF] ^ te2[(s3 >> 8) & 0xFF] ^ te3[s0 & 0xFF] ^ rk[k + 1]
            t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xFF] ^ te2[(s0 >> 8) & 0xFF] ^ te3[s1 & 0xFF] ^ rk[k + 2]
            t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xFF] ^ te2[(s1 >> 8) & 0xFF] ^ te3[s2 & 0xFF] ^ rk[k + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
            k += 4
        sb = _SBOX
        return (
            ((sb[s0 >> 24] << 24) | (sb[(s1 >> 16) & 0xFF] << 16) | (sb[(s2 >> 8) & 0xFF] << 8) | sb[s3 & 0xFF]) ^ rk[k],
            ((sb[s1 >> 24] << 24) | (sb[(s2 >> 16) & 0xFF] << 16) | (sb[(s3 >> 8) & 0xFF] << 8) | sb[s0 & 0xFF]) ^ rk[k + 1],
            ((sb[s2 >> 24] << 24) | (sb[(s3 >> 16) & 0xFF] << 16) | (sb[(s0 >> 8) & 0xFF] << 8) | sb[s1 & 0xFF]) ^ rk[k + 2],
            ((sb[s3 >> 24] << 24) | (sb[(s0 >> 16) & 0xFF] << 16) | (sb[(s1 >> 8) & 0xFF] << 8) | sb[s2 & 0xFF]) ^ rk[k + 3],
        )

    def decrypt_words(self, s0: int, s1: int, s2: int, s3: int):
        td0, td1, td2, td3 = _TD
        rk = self.dk
        s0 ^= rk[0]
        s1 ^= rk[1]
        s2 ^= rk[2]
        s3 ^= rk[3]
        k = 4
        for _ in range(self.rounds - 1):
            t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xFF] ^ td2[(s2 >> 8) & 0xFF] ^ td3[s1 & 0xFF] ^ rk[k]
            t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xFF] ^ td2[(s3 >> 8) & 0xFF] ^ td3[s2 & 0xFF] ^ rk[k + 1]
            t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xFF] ^ td2[(s0 >> 8) & 0xFF] ^ td3[s3 & 0xFF] ^ rk[k + 2]
            t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xFF] ^ td2[(s1 >> 8) & 0xFF] ^ td3[s0 & 0xFF] ^ rk[k + 3]
            s0, s1, s2, s3 = t0, t1, t2, t3
            k += 4
        isb = _INV_SBOX
        return (
            ((isb[s0 >> 24] << 24) | (isb[(s3 >> 16) & 0xFF] << 16) | (isb[(s2 >> 8) & 0xFF] << 8) | isb[s1 & 0xFF]) ^ rk[k],
            ((isb[s1 >> 24] << 24) | (isb[(s0 >> 16) & 0xFF] << 16) | (isb[(s3 >> 8) & 0xFF] << 8) | isb[s2 & 0xFF]) ^ rk[k + 1],
            ((isb[s2 >> 24] << 24) | (isb[(s1 >> 16) & 0xFF] << 16) | (isb[(s0 >> 8) & 0xFF] << 8) | isb[s3 & 0xFF]) ^ rk[k + 2],
            ((isb[s3 >> 24] << 24) | (isb[(s2 >> 16) & 0xFF] << 16) | (isb[(s1 >> 8) & 0xFF] << 8) | isb[s0 & 0xFF]) ^ rk[k + 3],
        )


def _pure_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    aes = _PureAES(key)
    p0, p1, p2, p3 = struct.unpack(">4I", iv)
    out = []
    unpack = struct.unpack_from
    pack = struct.pack
    for off in range(0, len(data), BLOCK_SIZE):
        b0, b1, b2, b3 = unpack(">4I", data, off)
        p0, p1, p2, p3 = aes.encrypt_words(b0 ^ p0, b1 ^ p1, b2 ^ p2, b3 ^ p3)
        out.append(pack(">4I", p0, p1, p2, p3))
    return b"".join(out)


def _pure_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    aes = _PureAES(key)
    p0, p1, p2, p3 = struct.unpack(">4I", iv)
    out = []
    unpack = struct.unpack_from
    pack = struct.pack
    for off in range(0, len(data), BLOCK_SIZE):
        c0, c1, c2, c3 = unpack(">4I", data, off)
        d0, d1, d2, d3 = aes.decrypt_words(c0, c1, c2, c3)
        out.append(pack(">4I", d0 ^ p0, d1 ^ p1, d2 ^ p2, d3 ^ p3))
        p0, p1, p2, p3 = c0, c1, c2, c3
    return b"".join(out)


def _check_key_iv(key, iv) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    if not isinstance(iv, (bytes, bytearray)) or len(iv) != BLOCK_SIZE:
        raise ValueError("AES IV must be 16 bytes")


def _use_fast(fast) -> bool:
    if fast is None:
        fast = USE_FAST_PATH
    return bool(fast) and HAVE_FAST_AES


def _run_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool, fast) -> bytes:
    global HAVE_FAST_AES
    if _use_fast(fast):
        try:
            return _fast_cbc(key, iv, data, encrypt)
        except (KeyboardInterrupt, SystemExit):  # pragma: no cover
            raise
        except BaseException:  # pragma: no cover - broken fast path: stop using it
            HAVE_FAST_AES = False
    if encrypt:
        return _pure_cbc_encrypt(key, iv, data)
    return _pure_cbc_decrypt(key, iv, data)


def aes_cbc_encrypt_raw(key: bytes, iv: bytes, data: bytes, fast=None) -> bytes:
    """AES-CBC encrypt without padding. ``data`` must be a multiple of 16 bytes."""
    _check_key_iv(key, iv)
    data = bytes(data)
    if len(data) % BLOCK_SIZE:
        raise ValueError("AES-CBC data must be a multiple of 16 bytes")
    if not data:
        return b""
    return _run_cbc(bytes(key), bytes(iv), data, True, fast)


def aes_cbc_decrypt_raw(key: bytes, iv: bytes, data: bytes, fast=None) -> bytes:
    """AES-CBC decrypt without removing padding. ``data`` must be a multiple of 16."""
    _check_key_iv(key, iv)
    data = bytes(data)
    if len(data) % BLOCK_SIZE:
        raise ValueError("AES-CBC ciphertext must be a multiple of 16 bytes")
    if not data:
        return b""
    return _run_cbc(bytes(key), bytes(iv), data, False, fast)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Add PKCS#7 padding (always 1..block_size bytes)."""
    n = block_size - (len(data) % block_size)
    return bytes(data) + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Remove PKCS#7 padding. Raises ValueError if the padding is not valid."""
    if not data or len(data) % block_size:
        raise ValueError("bad PKCS#7 padding: wrong length")
    n = data[-1]
    if n < 1 or n > block_size:
        raise ValueError("bad PKCS#7 padding")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("bad PKCS#7 padding")
    return bytes(data[:-n])


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-CBC encrypt ``plaintext`` and add PKCS#7 padding."""
    return aes_cbc_encrypt_raw(key, iv, pkcs7_pad(plaintext))


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-CBC decrypt and remove PKCS#7 padding (ValueError if it is bad)."""
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("AES-CBC ciphertext must be a non-empty multiple of 16 bytes")
    return pkcs7_unpad(aes_cbc_decrypt_raw(key, iv, ciphertext))


# ---------------------------------------------------------------------------
# RSA PKCS#1 v1.5 (type 2), TP-Link chunked style
# ---------------------------------------------------------------------------


def byte_len(n: int) -> int:
    """Length of the RSA modulus in bytes."""
    return (int(n).bit_length() + 7) // 8


def _random_nonzero_bytes(count: int) -> bytes:
    out = bytearray()
    while len(out) < count:
        chunk = secrets.token_bytes(count - len(out) + 8)
        out.extend(b for b in chunk if b != 0)
    return bytes(out[:count])


def rsa_pkcs1_v15_pad(message: bytes, k: int) -> bytes:
    """Build a PKCS#1 v1.5 type-2 encryption block of ``k`` bytes."""
    if len(message) > k - PKCS1_V15_OVERHEAD:
        raise ValueError("message too long for this RSA key")
    ps = _random_nonzero_bytes(k - 3 - len(message))
    return b"\x00\x02" + ps + b"\x00" + bytes(message)


def rsa_encrypt_chunked(n: int, e: int, plaintext: bytes) -> str:
    """RSA-encrypt ``plaintext`` the way TP-Link's web UI does.

    The plaintext is cut into chunks of ``byte_len(n) - 11`` bytes. Each chunk
    is PKCS#1 v1.5 (type 2) encrypted with fresh random non-zero padding. Each
    ciphertext is written as lower-case hex, zero-padded to ``2*byte_len(n)``
    characters, and the pieces are concatenated. Empty input gives "".
    """
    n = int(n)
    e = int(e)
    if n <= 0 or e <= 0:
        raise ValueError("bad RSA public key")
    k = byte_len(n)
    chunk = k - PKCS1_V15_OVERHEAD
    if chunk < 1:
        raise ValueError("RSA key is too small")
    plaintext = bytes(plaintext)
    width = 2 * k
    parts = []
    for off in range(0, len(plaintext), chunk):
        block = rsa_pkcs1_v15_pad(plaintext[off: off + chunk], k)
        c = pow(int.from_bytes(block, "big"), e, n)
        parts.append(format(c, "x").zfill(width))
    return "".join(parts)


def random_16_digit() -> str:
    """A random 16-digit decimal string with no leading zero (AES key / IV)."""
    low = 10 ** 15
    return str(low + secrets.randbelow(9 * low))
