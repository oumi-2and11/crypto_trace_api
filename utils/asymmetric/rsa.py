"""RSA-1024 — 从零实现，含 Level 2 Trace。

参考：PKCS#1 v2.2 (RFC 8017)
- Miller-Rabin 素性测试
- 扩展欧几里得求模逆
- PKCS#1 v1.5 签名填充
"""

import random
import math
from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output, hex_to_bytes, bytes_to_hex
from utils.common.validation import CryptoError


# ---- 大整数工具 ----

def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = _extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def _modinv(a: int, m: int) -> int:
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise CryptoError(2009, f"modular inverse does not exist for a={a}")
    return x % m


def _is_probable_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin 素性测试，k 轮。"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # 写 n-1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
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


def _generate_prime(bits: int) -> int:
    """生成指定位数的素数。"""
    while True:
        # 确保最高位为 1
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1  # 最高位和最低位置 1
        if _is_probable_prime(n):
            return n


# ---- PKCS#1 v1.5 签名填充 ----

# DigestInfo DER 编码头 (SHA-256)
_DIGEST_INFO_SHA256 = bytes([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
])

# DigestInfo DER 编码头 (SHA-1)
_DIGEST_INFO_SHA1 = bytes([
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
])


def _pkcs1_v15_encode(digest: bytes, em_len: int, hash_algo: str = "sha256") -> bytes:
    """EMSA-PKCS1-v1_5-ENCODE."""
    if hash_algo == "sha256":
        t = _DIGEST_INFO_SHA256 + digest
    elif hash_algo == "sha1":
        t = _DIGEST_INFO_SHA1 + digest
    else:
        raise CryptoError(1005, f"unsupported hash for RSA padding: {hash_algo}")

    t_len = len(t)
    if em_len < t_len + 11:
        raise CryptoError(2004, "intended encoded message length too short")

    ps_len = em_len - t_len - 3
    ps = b'\xff' * ps_len
    return b'\x00\x01' + ps + b'\x00' + t


def _pkcs1_v15_decode(em: bytes, hash_algo: str = "sha256") -> bytes:
    """EMSA-PKCS1-v1_5 验证时提取摘要。"""
    if len(em) < 11:
        raise CryptoError(2003, "encoded message too short")
    if em[0] != 0x00 or em[1] != 0x01:
        raise CryptoError(2003, "invalid PKCS#1 v1.5 padding")

    # 找 0x00 分隔符
    sep_idx = None
    for i in range(2, len(em)):
        if em[i] == 0x00:
            sep_idx = i
            break
        if em[i] != 0xFF:
            raise CryptoError(2003, "invalid PKCS#1 v1.5 padding (non-0xFF in PS)")

    if sep_idx is None or sep_idx < 10:
        raise CryptoError(2003, "invalid PKCS#1 v1.5 padding (no separator)")

    t = em[sep_idx + 1:]
    if hash_algo == "sha256":
        expected_prefix = _DIGEST_INFO_SHA256
        digest_len = 32
    elif hash_algo == "sha1":
        expected_prefix = _DIGEST_INFO_SHA1
        digest_len = 20
    else:
        raise CryptoError(1005, hash_algo)

    if not t.startswith(expected_prefix):
        raise CryptoError(2003, "DigestInfo algorithm mismatch")

    digest = t[len(expected_prefix):]
    if len(digest) != digest_len:
        raise CryptoError(2003, "digest length mismatch")

    return digest


# ---- 核心函数 ----

def _keygen_internal(bits: int = 1024, tc: TraceCollector = None):
    """RSA 密钥生成核心。返回 (n, e, d, p, q)。"""
    half = bits // 2

    p = _generate_prime(half)
    q = _generate_prime(half)
    while p == q:
        q = _generate_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if _gcd(e, phi) != 1:
        # 极罕见情况，换 e
        e = 3
        while _gcd(e, phi) != 1:
            e += 2

    d = _modinv(e, phi)

    if tc and tc.level >= 2:
        tc.add_step("keygen_params", {
            "bits": bits,
            "p_bits": p.bit_length(),
            "q_bits": q.bit_length(),
            "n_bits": n.bit_length(),
            "e": e,
            "d_bits": d.bit_length(),
            "p_head": hex(p)[:18] + "...",
            "q_head": hex(q)[:18] + "...",
            "n_head": hex(n)[:34] + "...",
        })

    return n, e, d, p, q


def _sign_internal(message: bytes, n: int, d: int,
                   hash_algo: str = "sha256",
                   tc: TraceCollector = None) -> bytes:
    """RSA 签名核心。"""
    if hash_algo == "sha256":
        from utils.hash.sha256 import digest
        h = digest(message)
    elif hash_algo == "sha1":
        from utils.hash.sha1 import digest as sha1_digest
        h = sha1_digest(message)
    else:
        raise CryptoError(1005, hash_algo)

    k = (n.bit_length() + 7) // 8
    em = _pkcs1_v15_encode(h, k, hash_algo)

    m = int.from_bytes(em, 'big')
    if m >= n:
        raise CryptoError(2004, "message representative out of range")

    s = pow(m, d, n)
    sig = s.to_bytes(k, 'big')

    if tc and tc.level >= 2:
        tc.add_step("sign_details", {
            "hash_algo": hash_algo,
            "digest_hex": h.hex(),
            "em_len": len(em),
            "k_bytes": k,
            "signature_bits": s.bit_length(),
        })

    return sig


def _verify_internal(message: bytes, signature: bytes, n: int, e: int,
                     hash_algo: str = "sha256",
                     tc: TraceCollector = None) -> bool:
    """RSA 验签核心。"""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        raise CryptoError(2003, f"signature length {len(signature)} != expected {k}")

    s = int.from_bytes(signature, 'big')
    if s >= n:
        raise CryptoError(2003, "signature representative out of range")

    m = pow(s, e, n)
    em_recovered = m.to_bytes(k, 'big')

    if hash_algo == "sha256":
        from utils.hash.sha256 import digest
        h = digest(message)
    elif hash_algo == "sha1":
        from utils.hash.sha1 import digest as sha1_digest
        h = sha1_digest(message)
    else:
        raise CryptoError(1005, hash_algo)

    try:
        em_expected = _pkcs1_v15_encode(h, k, hash_algo)
    except CryptoError:
        if tc and tc.level >= 2:
            tc.add_step("verify_details", {"result": "invalid_encoding"})
        return False

    valid = em_recovered == em_expected

    if tc and tc.level >= 2:
        tc.add_step("verify_details", {
            "hash_algo": hash_algo,
            "digest_hex": h.hex(),
            "result": "valid" if valid else "invalid",
        })

    return valid


# ---- API 接口 ----

def compute_keygen(bits: int = 1024, trace: bool = False,
                   trace_level: int = 1) -> dict:
    """RSA 密钥生成 API。"""
    tc = TraceCollector(enabled=trace, level=trace_level)
    with measure_time() as mt:
        tc.set_meta(algorithm="RSA", operation="keygen")

        if bits < 512 or bits > 2048:
            raise CryptoError(1004, f"bits={bits}, must be 512-2048")

        n, e, d, p, q = _keygen_internal(bits, tc)
        k = (n.bit_length() + 7) // 8

        tc.add_step("keygen_complete", {
            "n_hex_len": k * 2,
            "e": e,
        })

        result = {
            "n": n.to_bytes(k, 'big').hex(),
            "e": hex(e),
            "d": d.to_bytes(k, 'big').hex(),
            "p": p.to_bytes((p.bit_length() + 7) // 8, 'big').hex(),
            "q": q.to_bytes((q.bit_length() + 7) // 8, 'big').hex(),
            "bits": n.bit_length(),
        }

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": result,
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }


def compute_sign(raw: str, encoding: str, n_hex: str, d_hex: str,
                  hash_algo: str = "sha256", output: str = "hex",
                  trace: bool = False, trace_level: int = 1) -> dict:
    """RSA 签名 API。"""
    tc = TraceCollector(enabled=trace, level=trace_level)
    with measure_time() as mt:
        tc.set_meta(algorithm="RSA", operation="sign",
                    input_summary=TraceCollector.summarize_bytes(
                        parse_input(raw, encoding) if raw else b'', 16))

        message = parse_input(raw, encoding)
        n = int(n_hex, 16)
        d = int(d_hex, 16)

        if hash_algo not in ("sha256", "sha1"):
            raise CryptoError(1005, hash_algo)

        sig = _sign_internal(message, n, d, hash_algo, tc)
        sig_str = format_output(sig, output)

        result = {"signature": sig_str}

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": result,
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }


def compute_verify(raw: str, encoding: str, signature_raw: str,
                    sig_encoding: str, n_hex: str, e_hex: str,
                    hash_algo: str = "sha256", output: str = "hex",
                    trace: bool = False, trace_level: int = 1) -> dict:
    """RSA 验签 API。"""
    tc = TraceCollector(enabled=trace, level=trace_level)
    with measure_time() as mt:
        tc.set_meta(algorithm="RSA", operation="verify")

        message = parse_input(raw, encoding)
        sig_bytes = parse_input(signature_raw, sig_encoding)
        n = int(n_hex, 16)

        # e 可以是 "0x10001" 或 "65537" 或 hex
        if e_hex.startswith("0x") or e_hex.startswith("0X"):
            e = int(e_hex, 16)
        else:
            try:
                e = int(e_hex)
            except ValueError:
                e = int(e_hex, 16)

        if hash_algo not in ("sha256", "sha1"):
            raise CryptoError(1005, hash_algo)

        valid = _verify_internal(message, sig_bytes, n, e, hash_algo, tc)

        result = {"valid": valid}

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": result,
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }
