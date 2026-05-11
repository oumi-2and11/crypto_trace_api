"""SHA-3 (Keccak) — 从零实现，Level 1 Trace。

参考：FIPS 202
输出 SHA3-256 (32 bytes)。
"""

from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output
from utils.common.validation import CryptoError

_RATE = 136   # SHA3-256: 1088 bits = 136 bytes
_OUTPUT_LEN = 32

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets indexed as ROT[x][y]
_ROT = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
]

M64 = 0xFFFFFFFFFFFFFFFF


def _rot64(x, n):
    if n == 0:
        return x
    return ((x << n) | (x >> (64 - n))) & M64


def _keccak_f(state):
    """Keccak-f[1600]. state[x + 5*y] indexing."""
    for rc in _RC:
        # θ
        C = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
             for x in range(5)]
        for x in range(5):
            D = C[(x - 1) % 5] ^ _rot64(C[(x + 1) % 5], 1)
            for y in range(5):
                state[x + 5*y] ^= D
                state[x + 5*y] &= M64

        # ρ and π
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2*x + 3*y) % 5)] = _rot64(state[x + 5*y], _ROT[x][y])

        # χ
        for y in range(5):
            p = [B[x + 5*y] for x in range(5)]
            for x in range(5):
                state[x + 5*y] = (p[x] ^ ((~p[(x+1) % 5]) & p[(x+2) % 5])) & M64

        # ι
        state[0] ^= rc

    return state


def _sha3_pad(message: bytes, rate: int) -> bytes:
    buf = bytearray(message)
    buf.append(0x06)
    while len(buf) % rate != rate - 1:
        buf.append(0x00)
    buf.append(0x80)
    return bytes(buf)


def digest(data: bytes, trace_collector: TraceCollector = None) -> bytes:
    padded = _sha3_pad(data, _RATE)
    state = [0] * 25

    for offset in range(0, len(padded), _RATE):
        block = padded[offset:offset + _RATE]
        for i in range(len(block) // 8):
            state[i] ^= int.from_bytes(block[i*8:i*8+8], 'little')
        rem = len(block) % 8
        if rem:
            partial = block[-rem:] + b'\x00' * (8 - rem)
            state[len(block) // 8] ^= int.from_bytes(partial, 'little')
        state = _keccak_f(state)

    out = b''
    for i in range(25):
        out += state[i].to_bytes(8, 'little')
    return out[:_OUTPUT_LEN]


def compute(raw: str, encoding: str = "hex", output: str = "hex",
            trace: bool = False, trace_level: int = 1) -> dict:
    tc = TraceCollector(enabled=trace, level=trace_level)
    tc.set_meta(algorithm="SHA3-256", operation="digest")

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
