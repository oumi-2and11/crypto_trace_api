"""SHA-256 — 从零实现，含 Level 2 Trace（padding/W[t]/寄存器采样）。

参考：FIPS 180-4
"""

import struct
from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output
from utils.common.validation import CryptoError

# ---- 常量 ----

_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

_H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

_MASK32 = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _shr(x: int, n: int) -> int:
    return x >> n


def _ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & _MASK32 & z)


def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def _sig0(x: int) -> int:
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _sig1(x: int) -> int:
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _sig0_lower(x: int) -> int:
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)


def _sig1_lower(x: int) -> int:
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)


def _pad(message: bytes) -> bytes:
    ml = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += struct.pack('>Q', ml)
    return message


def _compress(block: bytes, h: list, tc: TraceCollector = None,
              block_index: int = 0) -> list:
    assert len(block) == 64

    # 消息调度
    W = list(struct.unpack('>16I', block))
    for t in range(16, 64):
        W.append((_sig1_lower(W[t - 2]) + W[t - 7] +
                   _sig0_lower(W[t - 15]) + W[t - 16]) & _MASK32)

    if tc and tc.level >= 2:
        tc.add_step("message_schedule", {
            "block": block_index,
            "W0_15_head": [f"0x{w:08x}" for w in W[:4]],
            "W16_63_head": [f"0x{w:08x}" for w in W[16:20]],
        })

    a, b, c, d, e, f, g, hh = h

    if tc and tc.level >= 2:
        tc.add_step("round_init", {
            "block": block_index,
            "a": f"0x{a:08x}", "e": f"0x{e:08x}",
        })

    for t in range(64):
        T1 = (hh + _sig1(e) + _ch(e, f, g) + _K[t] + W[t]) & _MASK32
        T2 = (_sig0(a) + _maj(a, b, c)) & _MASK32
        hh = g
        g = f
        f = e
        e = (d + T1) & _MASK32
        d = c
        c = b
        b = a
        a = (T1 + T2) & _MASK32

        if tc and tc.level >= 2 and t in (0, 1, 15, 31, 48, 63):
            tc.add_step("round_sample", {
                "block": block_index, "t": t,
                "a": f"0x{a:08x}", "e": f"0x{e:08x}",
            })

    return [
        (h[0] + a) & _MASK32, (h[1] + b) & _MASK32,
        (h[2] + c) & _MASK32, (h[3] + d) & _MASK32,
        (h[4] + e) & _MASK32, (h[5] + f) & _MASK32,
        (h[6] + g) & _MASK32, (h[7] + hh) & _MASK32,
    ]


def digest(data: bytes, trace_collector: TraceCollector = None) -> bytes:
    """计算 SHA-256 摘要。"""
    padded = _pad(data)
    h = list(_H0)

    if trace_collector and trace_collector.level >= 2:
        trace_collector.add_step("padding", {
            "original_len": len(data),
            "padded_len": len(padded),
            "bit_len": len(data) * 8,
            "num_blocks": len(padded) // 64,
        })

    for i in range(0, len(padded), 64):
        block = padded[i:i + 64]
        h = _compress(block, h, trace_collector, block_index=i // 64)

    return b''.join(struct.pack('>I', v) for v in h)


def compute(raw: str, encoding: str = "hex", output: str = "hex",
            trace: bool = False, trace_level: int = 1) -> dict:
    """SHA-256 计算接口。"""
    tc = TraceCollector(enabled=trace, level=trace_level)
    tc.set_meta(algorithm="SHA-256", operation="digest")

    with measure_time() as mt:
        data_bytes = parse_input(raw, encoding)
        tc.add_step("input", TraceCollector.summarize_bytes(data_bytes))

        result_bytes = digest(data_bytes, tc)

        tc.add_step("output", TraceCollector.summarize_bytes(result_bytes))
        result_str = format_output(result_bytes, output)

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": {
            "digest": result_str,
            "output_encoding": output,
        },
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }
