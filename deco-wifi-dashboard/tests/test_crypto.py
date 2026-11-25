"""Tests for decodash.crypto (AES-128-CBC + PKCS#7, TP-Link style RSA)."""

from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from decodash import crypto  # noqa: E402
from tests.mock_deco import generate_rsa_keypair, pkcs1_v15_unpad  # noqa: E402

# NIST SP 800-38A, F.2.1 / F.2.2 (CBC-AES128)
NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
NIST_CT = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516"
    "3ff1caa1681fac09120eca307586e1a7"
)

# FIPS-197 Appendix C (single block; CBC with a zero IV is the same as ECB)
FIPS_PT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS_VECTORS = (
    (bytes(range(16)), "69c4e0d86a7b0430d8cdb78070b4c55a"),
    (bytes(range(24)), "dda97ca4864cdfe06eaf70a0ec0d7191"),
    (bytes(range(32)), "8ea2b7ca516745bfeafc49904b496089"),
)

PATHS = (False, True) if crypto.HAVE_FAST_AES else (False,)


class AesVectorTests(unittest.TestCase):
    def test_nist_cbc_encrypt_raw(self):
        for fast in PATHS:
            with self.subTest(fast=fast):
                self.assertEqual(crypto.aes_cbc_encrypt_raw(NIST_KEY, NIST_IV, NIST_PT, fast=fast), NIST_CT)

    def test_nist_cbc_decrypt_raw(self):
        for fast in PATHS:
            with self.subTest(fast=fast):
                self.assertEqual(crypto.aes_cbc_decrypt_raw(NIST_KEY, NIST_IV, NIST_CT, fast=fast), NIST_PT)

    def test_nist_with_pkcs7_pure_path(self):
        with mock.patch.object(crypto, "USE_FAST_PATH", False):
            ct = crypto.aes_cbc_encrypt(NIST_KEY, NIST_IV, NIST_PT)
            # 64 bytes of data -> 4 vector blocks + one full padding block
            self.assertEqual(len(ct), 80)
            self.assertEqual(ct[:64], NIST_CT)
            last = crypto.aes_cbc_encrypt_raw(NIST_KEY, NIST_CT[-16:], b"\x10" * 16, fast=False)
            self.assertEqual(ct[64:], last)
            self.assertEqual(crypto.aes_cbc_decrypt(NIST_KEY, NIST_IV, ct), NIST_PT)

    def test_fips197_single_blocks(self):
        for key, expected in FIPS_VECTORS:
            for fast in PATHS:
                with self.subTest(key_bits=len(key) * 8, fast=fast):
                    ct = crypto.aes_cbc_encrypt_raw(key, bytes(16), FIPS_PT, fast=fast)
                    self.assertEqual(ct.hex(), expected)
                    self.assertEqual(crypto.aes_cbc_decrypt_raw(key, bytes(16), ct, fast=fast), FIPS_PT)

    def test_deco_style_ascii_key_round_trip(self):
        key = crypto.random_16_digit().encode("ascii")
        iv = crypto.random_16_digit().encode("ascii")
        text = '{"operation":"read","params":{"device_mac":"default"}}'.encode("utf-8")
        with mock.patch.object(crypto, "USE_FAST_PATH", False):
            ct = crypto.aes_cbc_encrypt(key, iv, text)
            self.assertEqual(crypto.aes_cbc_decrypt(key, iv, ct), text)


@unittest.skipUnless(crypto.HAVE_FAST_AES, "cryptography is not installed")
class AesCrossCheckTests(unittest.TestCase):
    def test_pure_matches_cryptography(self):
        for key_len in (16, 24, 32):
            for length in list(range(0, 40)) + [255, 256, 1000, 4097]:
                key = os.urandom(key_len)
                iv = os.urandom(16)
                data = os.urandom(length)
                with self.subTest(key_len=key_len, length=length):
                    fast_ct = crypto.aes_cbc_encrypt(key, iv, data)
                    with mock.patch.object(crypto, "USE_FAST_PATH", False):
                        pure_ct = crypto.aes_cbc_encrypt(key, iv, data)
                        self.assertEqual(pure_ct, fast_ct)
                        self.assertEqual(crypto.aes_cbc_decrypt(key, iv, fast_ct), data)
                    self.assertEqual(crypto.aes_cbc_decrypt(key, iv, pure_ct), data)

    def test_fast_path_is_used_by_default(self):
        with mock.patch.object(crypto, "_pure_cbc_encrypt", side_effect=AssertionError("pure used")):
            crypto.aes_cbc_encrypt(NIST_KEY, NIST_IV, b"hello")

    def test_forcing_pure_path_skips_cryptography(self):
        with mock.patch.object(crypto, "USE_FAST_PATH", False), \
                mock.patch.object(crypto, "_fast_cbc", side_effect=AssertionError("fast used")):
            ct = crypto.aes_cbc_encrypt(NIST_KEY, NIST_IV, b"hello")
            self.assertEqual(crypto.aes_cbc_decrypt(NIST_KEY, NIST_IV, ct), b"hello")


class Pkcs7Tests(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(crypto.pkcs7_pad(b""), b"\x10" * 16)
        for fast in PATHS:
            with self.subTest(fast=fast), mock.patch.object(crypto, "USE_FAST_PATH", fast):
                ct = crypto.aes_cbc_encrypt(NIST_KEY, NIST_IV, b"")
                self.assertEqual(len(ct), 16)
                self.assertEqual(crypto.aes_cbc_decrypt(NIST_KEY, NIST_IV, ct), b"")

    def test_exact_block_multiple_gets_a_full_extra_block(self):
        for length in (16, 32, 48):
            data = bytes(range(length))
            self.assertEqual(crypto.pkcs7_pad(data), data + b"\x10" * 16)
            for fast in PATHS:
                with self.subTest(length=length, fast=fast), mock.patch.object(crypto, "USE_FAST_PATH", fast):
                    ct = crypto.aes_cbc_encrypt(NIST_KEY, NIST_IV, data)
                    self.assertEqual(len(ct), length + 16)
                    self.assertEqual(crypto.aes_cbc_decrypt(NIST_KEY, NIST_IV, ct), data)

    def test_partial_block_lengths(self):
        for length in range(1, 16):
            padded = crypto.pkcs7_pad(b"a" * length)
            self.assertEqual(len(padded), 16)
            self.assertEqual(padded[-1], 16 - length)
            self.assertEqual(crypto.pkcs7_unpad(padded), b"a" * length)

    def test_bad_padding_raises_value_error(self):
        bad_plain_blocks = (
            b"A" * 15 + b"\x00",           # zero is never valid
            b"A" * 15 + b"\x11",           # bigger than the block size
            b"A" * 13 + b"\x02\x03\x03",   # last byte says 3 but bytes differ
            b"A" * 14 + b"\x01\x02",       # says 2, previous byte is 1
        )
        for block in bad_plain_blocks:
            ct = crypto.aes_cbc_encrypt_raw(NIST_KEY, NIST_IV, block, fast=False)
            for fast in PATHS:
                with self.subTest(block=block, fast=fast), mock.patch.object(crypto, "USE_FAST_PATH", fast):
                    with self.assertRaises(ValueError):
                        crypto.aes_cbc_decrypt(NIST_KEY, NIST_IV, ct)

    def test_bad_lengths_raise_value_error(self):
        for fast in PATHS:
            with mock.patch.object(crypto, "USE_FAST_PATH", fast):
                for bad in (b"", b"x" * 15, b"x" * 17):
                    with self.subTest(fast=fast, length=len(bad)):
                        with self.assertRaises(ValueError):
                            crypto.aes_cbc_decrypt(NIST_KEY, NIST_IV, bad)
        with self.assertRaises(ValueError):
            crypto.pkcs7_unpad(b"")
        with self.assertRaises(ValueError):
            crypto.aes_cbc_encrypt_raw(NIST_KEY, NIST_IV, b"abc")

    def test_wrong_key_or_iv_size(self):
        with self.assertRaises(ValueError):
            crypto.aes_cbc_encrypt(b"short", NIST_IV, b"x")
        with self.assertRaises(ValueError):
            crypto.aes_cbc_encrypt(NIST_KEY, b"short", b"x")
        with self.assertRaises(ValueError):
            crypto.aes_cbc_decrypt(NIST_KEY, b"x" * 17, b"y" * 16)


class RsaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = {512: generate_rsa_keypair(512), 1024: generate_rsa_keypair(1024)}

    def _check(self, key, plaintext: bytes):
        k = crypto.byte_len(key.n)
        self.assertEqual(k, key.k)
        out = crypto.rsa_encrypt_chunked(key.n, key.e, plaintext)
        self.assertIsInstance(out, str)
        self.assertEqual(out, out.lower())
        chunk = k - 11
        expected_blocks = (len(plaintext) + chunk - 1) // chunk
        self.assertEqual(len(out), expected_blocks * 2 * k)
        recovered = b""
        for i in range(expected_blocks):
            hex_block = out[i * 2 * k:(i + 1) * 2 * k]
            block = key.raw_decrypt(int(hex_block, 16))
            self.assertEqual(block[:2], b"\x00\x02")
            message, ps = pkcs1_v15_unpad(block)
            self.assertGreaterEqual(len(ps), 8)
            self.assertNotIn(0, ps)
            self.assertEqual(message, plaintext[i * chunk:(i + 1) * chunk])
            recovered += message
        self.assertEqual(recovered, plaintext)
        self.assertEqual(key.decrypt_chunked_hex(out), plaintext)
        return out

    def test_chunking_512_and_1024(self):
        for bits, key in self.keys.items():
            k = key.k
            for length in (0, 1, 16, k - 12, k - 11, k - 10, 2 * (k - 11), 3 * (k - 11) + 7):
                with self.subTest(bits=bits, length=length):
                    self._check(key, os.urandom(length))

    def test_sign_text_like_the_deco(self):
        key = self.keys[512]
        text = ("k=%s&i=%s&h=%s&s=%d" % (crypto.random_16_digit(), crypto.random_16_digit(),
                                          "0" * 32, 123456789 + 64)).encode("ascii")
        out = self._check(key, text)
        self.assertEqual(len(out) % 128, 0)
        self.assertGreaterEqual(len(out) // 128, 2)  # longer than one 53-byte chunk

    def test_empty_plaintext_gives_empty_string(self):
        self.assertEqual(crypto.rsa_encrypt_chunked(self.keys[512].n, 65537, b""), "")

    def test_padding_is_random(self):
        key = self.keys[512]
        a = crypto.rsa_encrypt_chunked(key.n, key.e, b"same text")
        b = crypto.rsa_encrypt_chunked(key.n, key.e, b"same text")
        self.assertNotEqual(a, b)

    def test_hex_is_zero_padded(self):
        # With e=1 the "ciphertext" is the padded block itself, which always
        # starts with 0x00 0x02, so its natural hex is too short and must be padded.
        key = self.keys[512]
        out = crypto.rsa_encrypt_chunked(key.n, 1, b"hello")
        self.assertEqual(len(out), 2 * key.k)
        self.assertTrue(out.startswith("0002"))
        message, ps = pkcs1_v15_unpad(bytes.fromhex(out))
        self.assertEqual(message, b"hello")
        self.assertEqual(len(ps), key.k - 3 - 5)

    def test_odd_bit_length_modulus(self):
        key = generate_rsa_keypair(1023)
        self.assertEqual(key.n.bit_length(), 1023)
        self.assertEqual(crypto.byte_len(key.n), 128)
        self._check(key, os.urandom(300))

    def test_tiny_key_rejected(self):
        with self.assertRaises(ValueError):
            crypto.rsa_encrypt_chunked(0xFFFF, 3, b"x")


def _load_cryptography_rsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        return padding, rsa
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:  # missing, or a broken binary install (pyo3 PanicException)
        return None


_CRYPTO_RSA = _load_cryptography_rsa()


@unittest.skipUnless(_CRYPTO_RSA, "cryptography (RSA) is not usable here")
class RsaCryptographyOracleTests(unittest.TestCase):
    """Independent check: a real PKCS#1 v1.5 implementation must decrypt our blocks."""

    @staticmethod
    def _private_key(bits: int):
        from tests.mock_deco import random_prime
        import math
        padding, rsa = _CRYPTO_RSA
        if bits >= 1024:
            return rsa.generate_private_key(public_exponent=65537, key_size=bits)
        while True:  # cryptography refuses to *generate* 512-bit keys, but loads them
            p, q = random_prime(bits // 2), random_prime(bits - bits // 2)
            n = p * q
            if p != q and n.bit_length() == bits and math.gcd(65537, (p - 1) * (q - 1)) == 1:
                break
        d = pow(65537, -1, (p - 1) * (q - 1))
        numbers = rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), rsa.rsa_crt_iqmp(p, q),
                                        rsa.RSAPublicNumbers(65537, n))
        try:
            return numbers.private_key(unsafe_skip_rsa_key_validation=True)
        except TypeError:  # older cryptography
            return numbers.private_key()

    def test_cryptography_decrypts_every_chunk(self):
        padding, _rsa = _CRYPTO_RSA
        for bits in (512, 1024):
            try:
                key = self._private_key(bits)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as err:
                self.skipTest("cannot build a %d-bit key: %s" % (bits, type(err).__name__))
            pub = key.public_key().public_numbers()
            k = crypto.byte_len(pub.n)
            for length in (1, k - 11, k - 10, 3 * (k - 11) + 5):
                with self.subTest(bits=bits, length=length):
                    plaintext = os.urandom(length)
                    out = crypto.rsa_encrypt_chunked(pub.n, pub.e, plaintext)
                    self.assertEqual(len(out) % (2 * k), 0)
                    recovered = b"".join(
                        key.decrypt(bytes.fromhex(out[i:i + 2 * k]), padding.PKCS1v15())
                        for i in range(0, len(out), 2 * k))
                    self.assertEqual(recovered, plaintext)

    def test_cryptography_ciphertext_round_trips_through_mock_unpad(self):
        # The other direction: what a reference PKCS#1 v1.5 encryptor makes is what
        # the mock Deco (and so our tests) accept.
        padding, _rsa = _CRYPTO_RSA
        key = self._private_key(512)
        pub = key.public_key()
        n = pub.public_numbers().n
        d = key.private_numbers().d
        k = crypto.byte_len(n)
        message = b"k=1234567890123456&i=6543210987654321&h=0123456789abcdef0123456789abcdef"[:k - 11]
        block = pow(int.from_bytes(pub.encrypt(message, padding.PKCS1v15()), "big"), d, n).to_bytes(k, "big")
        self.assertEqual(pkcs1_v15_unpad(block)[0], message)


class RandomDigitsTests(unittest.TestCase):
    def test_random_16_digit(self):
        seen = set()
        for _ in range(200):
            value = crypto.random_16_digit()
            self.assertEqual(len(value), 16)
            self.assertTrue(value.isdigit())
            self.assertNotEqual(value[0], "0")
            self.assertTrue(10 ** 15 <= int(value) < 10 ** 16)
            seen.add(value)
        self.assertGreater(len(seen), 190)

    def test_byte_len(self):
        self.assertEqual(crypto.byte_len(255), 1)
        self.assertEqual(crypto.byte_len(256), 2)
        self.assertEqual(crypto.byte_len((1 << 512) - 1), 64)
        self.assertEqual(crypto.byte_len(1 << 1023), 128)


if __name__ == "__main__":
    unittest.main()
