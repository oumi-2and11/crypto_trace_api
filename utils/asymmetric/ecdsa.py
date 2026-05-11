"""ECDSA 签名 — 基于自写 ECC secp160r1，含 Level 2 Trace。

参考：SEC 1: Elliptic Curve Cryptography (ECDSA 签名/验签)
"""

import random
from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output
from utils.common.validation import CryptoError
from utils.asymmetric.ecc import (
    _P, _N, _Gx, _Gy, _scalar_mult, _point_add, _is_on_curve, INF,
)


def _sign_internal(message_hash: bytes, private_key: int,
                   tc: TraceCollector = None) -> tuple:
    """ECDSA 签名核心。返回 (r, s)。"""
    z = int.from_bytes(message_hash, 'big')

    while True:
        k = random.randrange(1, _N)
        point = _scalar_mult(k, (_Gx, _Gy))
        r = point[0] % _N
        if r == 0:
            continue

        k_inv = pow(k, -1, _N)
        s = (k_inv * (z + r * private_key)) % _N
        if s == 0:
            continue

        if tc and tc.level >= 2:
            tc.add_step("ecdsa_sign", {
                "k_bits": k.bit_length(),
                "r": hex(r),
                "s": hex(s),
                "point_x_head": hex(point[0])[:20] + "...",
            })
        break

    return (r, s)


def _verify_internal(message_hash: bytes, r: int, s: int,
                     public_key: tuple,
                     tc: TraceCollector = None) -> bool:
    """ECDSA 验签核心。"""
    if not (1 <= r < _N and 1 <= s < _N):
        if tc and tc.level >= 2:
            tc.add_step("ecdsa_verify", {"result": "invalid_range"})
        return False

    z = int.from_bytes(message_hash, 'big')
    s_inv = pow(s, -1, _N)
    u1 = (z * s_inv) % _N
    u2 = (r * s_inv) % _N

    point = _point_add(
        _scalar_mult(u1, (_Gx, _Gy)),
        _scalar_mult(u2, public_key),
    )

    if point[0] is None:
        if tc and tc.level >= 2:
            tc.add_step("ecdsa_verify", {"result": "point_at_infinity"})
        return False

    v = point[0] % _N
    valid = (v == r)

    if tc and tc.level >= 2:
        tc.add_step("ecdsa_verify", {
            "u1_bits": u1.bit_length(),
            "u2_bits": u2.bit_length(),
            "v": hex(v),
            "r": hex(r),
            "result": "valid" if valid else "invalid",
        })

    return valid


# ---- API 接口 ----

def compute_sign(raw: str, encoding: str,
                  private_key_hex: str,
                  hash_algo: str = "sha256",
                  output: str = "hex",
                  trace: bool = False, trace_level: int = 1) -> dict:
    """ECDSA 签名 API。"""
    tc = TraceCollector(enabled=trace, level=trace_level)
    with measure_time() as mt:
        tc.set_meta(algorithm="ECDSA", operation="sign",
                    input_summary=TraceCollector.summarize_bytes(
                        parse_input(raw, encoding) if raw else b'', 16))

        message = parse_input(raw, encoding)

        if hash_algo == "sha256":
            from utils.hash.sha256 import digest
            h = digest(message)
        elif hash_algo == "sha1":
            from utils.hash.sha1 import digest as sha1_digest
            h = sha1_digest(message)
        else:
            raise CryptoError(1005, hash_algo)

        # 截断到曲线阶的位长度 (160 bits = 20 bytes)
        h_trunc = h[:20] if len(h) > 20 else h

        priv = int(private_key_hex, 16)
        if not (1 <= priv < _N):
            raise CryptoError(2008, "private key out of range")

        r, s = _sign_internal(h_trunc, priv, tc)

        # 编码 r, s 各 20 字节
        r_bytes = r.to_bytes(20, 'big')
        s_bytes = s.to_bytes(20, 'big')
        sig_hex = r_bytes.hex() + s_bytes.hex()

        result = {
            "r": r_bytes.hex(),
            "s": s_bytes.hex(),
            "signature": sig_hex,
        }

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": result,
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }


def compute_verify(raw: str, encoding: str,
                    r_hex: str, s_hex: str,
                    pub_x_hex: str, pub_y_hex: str,
                    hash_algo: str = "sha256",
                    output: str = "hex",
                    trace: bool = False, trace_level: int = 1) -> dict:
    """ECDSA 验签 API。"""
    tc = TraceCollector(enabled=trace, level=trace_level)
    with measure_time() as mt:
        tc.set_meta(algorithm="ECDSA", operation="verify")

        message = parse_input(raw, encoding)

        if hash_algo == "sha256":
            from utils.hash.sha256 import digest
            h = digest(message)
        elif hash_algo == "sha1":
            from utils.hash.sha1 import digest as sha1_digest
            h = sha1_digest(message)
        else:
            raise CryptoError(1005, hash_algo)

        h_trunc = h[:20] if len(h) > 20 else h

        r = int(r_hex, 16)
        s = int(s_hex, 16)
        pub_x = int(pub_x_hex, 16)
        pub_y = int(pub_y_hex, 16)

        if not _is_on_curve(pub_x, pub_y):
            raise CryptoError(2007, "public key point not on curve")

        valid = _verify_internal(h_trunc, r, s, (pub_x, pub_y), tc)

        result = {"valid": valid}

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": result,
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }
