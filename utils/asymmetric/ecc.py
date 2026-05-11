"""ECC-160 — 从零实现 secp160r1 曲线，含 Level 2 Trace。

参考：SEC 2: Recommended Elliptic Curve Domain Parameters (secp160r1)
- 有限域 Fp 运算
- 椭圆曲线点运算：点加、倍点、标量乘
"""

import random
from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.validation import CryptoError


# ---- secp160r1 曲线参数 ----

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF
_A = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC
_B = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45
_Gx = 0x4A96B5688EF573284664698968C38BB913CBFC82
_Gy = 0x23A628553168947D59DCC912042351377AC5FB32
_N = 0x0100000000000000000001F4C8F927AED3CA752257  # 阶
_H = 1  # 辅因子

# 无穷远点
INF = (None, None)


def _is_on_curve(px: int, py: int) -> bool:
    """验证点是否在曲线上。"""
    if px is None:
        return True
    lhs = (py * py) % _P
    rhs = (px * px * px + _A * px + _B) % _P
    return lhs == rhs


def _point_add(p1: tuple, p2: tuple) -> tuple:
    """椭圆曲线点加。"""
    x1, y1 = p1
    x2, y2 = p2

    if x1 is None:
        return p2
    if x2 is None:
        return p1

    if x1 == x2:
        if y1 == y2:
            return _point_double(p1)
        else:
            return INF

    lam = ((y2 - y1) * pow(x2 - x1, -1, _P)) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_double(p: tuple) -> tuple:
    """椭圆曲线倍点。"""
    x, y = p
    if x is None:
        return INF

    lam = ((3 * x * x + _A) * pow(2 * y, -1, _P)) % _P
    x3 = (lam * lam - 2 * x) % _P
    y3 = (lam * (x - x3) - y) % _P
    return (x3, y3)


def _scalar_mult(k: int, p: tuple) -> tuple:
    """标量乘：k * P，使用 double-and-add。"""
    if k == 0 or p[0] is None:
        return INF

    if k < 0:
        k = -k
        p = (p[0], (-p[1]) % _P)

    result = INF
    addend = p
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        k >>= 1

    return result


# ---- 密钥生成 ----

def _keygen_internal(tc: TraceCollector = None):
    """ECC 密钥生成，返回 (public_key, private_key)。"""
    d = random.randrange(1, _N)
    q = _scalar_mult(d, (_Gx, _Gy))

    if not _is_on_curve(q[0], q[1]):
        raise CryptoError(2006, "generated public key not on curve")

    if tc and tc.level >= 2:
        tc.add_step("ecc_keygen", {
            "curve": "secp160r1",
            "p_bits": _P.bit_length(),
            "n_bits": _N.bit_length(),
            "private_key_bits": d.bit_length(),
            "pub_x_head": hex(q[0])[:20] + "...",
            "pub_y_head": hex(q[1])[:20] + "...",
            "point_on_curve": True,
        })

    return q, d


# ---- API 接口 ----

def compute_keygen(trace: bool = False, trace_level: int = 1) -> dict:
    """ECC 密钥生成 API。"""
    tc = TraceCollector(enabled=trace, level=trace_level)
    with measure_time() as mt:
        tc.set_meta(algorithm="ECC", operation="keygen")

        pub, priv = _keygen_internal(tc)
        pub_bytes = pub[0].to_bytes(20, 'big') + pub[1].to_bytes(20, 'big')
        priv_bytes = priv.to_bytes(20, 'big')

        result = {
            "public_key_x": pub[0].to_bytes(20, 'big').hex(),
            "public_key_y": pub[1].to_bytes(20, 'big').hex(),
            "private_key": priv_bytes.hex(),
            "curve": "secp160r1",
        }

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": result,
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }


def validate_point(x_hex: str, y_hex: str) -> bool:
    """验证点是否在 secp160r1 上。"""
    x = int(x_hex, 16)
    y = int(y_hex, 16)
    return _is_on_curve(x, y)
