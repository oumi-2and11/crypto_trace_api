"""SHA-1 — 从零实现，Level 1 Trace。

参考：FIPS 180-4
"""

import struct
from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output
from utils.common.validation import CryptoError

_H0 = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
_K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
_MASK = 0xFFFFFFFF


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & _MASK


def _pad(message: bytes) -> bytes:
    ml = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += struct.pack('>Q', ml)
    return message


def _compress(block: bytes, h: list) -> list:
    assert len(block) == 64
    W = list(struct.unpack('>16I', block))
    for t in range(16, 80):
        W.append(_rotl(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1))

    a, b, c, d, e = h
    for t in range(80):
        if t < 20:
            f = (b & c) | (~b & _MASK & d)
            k = _K[0]
        elif t < 40:
            f = b ^ c ^ d
            k = _K[1]
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
            k = _K[2]
        else:
            f = b ^ c ^ d
            k = _K[3]
        T = (_rotl(a, 5) + f + e + k + W[t]) & _MASK
        e = d
        d = c
        c = _rotl(b, 30)
        b = a
        a = T

    return [
        (h[0] + a) & _MASK, (h[1] + b) & _MASK,
        (h[2] + c) & _MASK, (h[3] + d) & _MASK,
        (h[4] + e) & _MASK,
    ]


def digest(data: bytes, trace_collector: TraceCollector = None) -> bytes:
    padded = _pad(data)
    h = list(_H0)
    for i in range(0, len(padded), 64):
        h = _compress(padded[i:i+64], h)
    return b''.join(struct.pack('>I', v) for v in h)


def compute(raw: str, encoding: str = "hex", output: str = "hex",
            trace: bool = False, trace_level: int = 1) -> dict:
    tc = TraceCollector(enabled=trace, level=trace_level)
    tc.set_meta(algorithm="SHA-1", operation="digest")

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
