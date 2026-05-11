"""RIPEMD-160 — 从零实现，Level 1 Trace。

参考：RIPEMD-160 规范
"""

import struct
from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output
from utils.common.validation import CryptoError

_H0 = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
_MASK = 0xFFFFFFFF

_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

_RL = [
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13,
]
_RR = [
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11,
]
_SL = [
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6,
]
_SR = [
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11,
]


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & _MASK


def _fl(j, b, c, d):
    """左路布尔函数。"""
    if j < 16: return b ^ c ^ d
    if j < 32: return (b & c) | ((~b & _MASK) & d)
    if j < 48: return (b | (~c & _MASK)) ^ d
    if j < 64: return (b & d) | (c & (~d & _MASK))
    return b ^ (c | (~d & _MASK))


def _fr(j, b, c, d):
    """右路布尔函数（与左路顺序相反）。"""
    if j < 16: return b ^ (c | (~d & _MASK))
    if j < 32: return (b & d) | (c & (~d & _MASK))
    if j < 48: return (b | (~c & _MASK)) ^ d
    if j < 64: return (b & c) | ((~b & _MASK) & d)
    return b ^ c ^ d


def _pad(message: bytes) -> bytes:
    ml = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += struct.pack('<Q', ml)
    return message


def _compress(block: bytes, h: list) -> list:
    X = list(struct.unpack('<16I', block))

    al, bl, cl, dl, el = h
    ar, br, cr, dr, er = h

    for j in range(80):
        rnd = j // 16
        # 左路
        t = (al + _fl(j, bl, cl, dl) + X[_RL[j]] + _KL[rnd]) & _MASK
        t = (_rotl32(t, _SL[j]) + el) & _MASK
        al = el
        el = dl
        dl = _rotl32(cl, 10)
        cl = bl
        bl = t

        # 右路
        t = (ar + _fr(j, br, cr, dr) + X[_RR[j]] + _KR[rnd]) & _MASK
        t = (_rotl32(t, _SR[j]) + er) & _MASK
        ar = er
        er = dr
        dr = _rotl32(cr, 10)
        cr = br
        br = t

    t = (h[1] + cl + dr) & _MASK
    h[1] = (h[2] + dl + er) & _MASK
    h[2] = (h[3] + el + ar) & _MASK
    h[3] = (h[4] + al + br) & _MASK
    h[4] = (h[0] + bl + cr) & _MASK
    h[0] = t
    return h


def digest(data: bytes, trace_collector: TraceCollector = None) -> bytes:
    padded = _pad(data)
    h = list(_H0)
    for i in range(0, len(padded), 64):
        h = _compress(padded[i:i+64], h)
    return b''.join(struct.pack('<I', v) for v in h)


def compute(raw: str, encoding: str = "hex", output: str = "hex",
            trace: bool = False, trace_level: int = 1) -> dict:
    tc = TraceCollector(enabled=trace, level=trace_level)
    tc.set_meta(algorithm="RIPEMD-160", operation="digest")

    with measure_time() as mt:
        data_bytes = parse_input(raw, encoding)
        tc.add_step("input", TraceCollector.summarize_bytes(data_bytes))

        result_bytes = digest(data_bytes, tc)

        tc.add_step("output", TraceCollector.summarize_bytes(result_bytes))
        result_str = format_output(result_bytes, output)

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": {"digest": result_str, "output_encoding": output},
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }
