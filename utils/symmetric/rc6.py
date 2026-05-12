"""RC6 — 从零实现，含 Level 1 Trace。

参考：Rivest, Robshaw, Sidney, Yin. "The RC6 Block Cipher" (1998)
- RC6-32/20/b：w=32, r=20, 可变长度密钥 b 字节
- 128-bit 分组 (4 × 32-bit 字), 128/192/256-bit 密钥
- 数据依赖旋转、模乘法
"""

import struct
from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output
from utils.common.validation import CryptoError

_W = 32          # 字长 (bits)
_R = 20          # 轮数
_P32 = 0xB7E15163  # P_w = odd((e-2) * 2^w)
_Q32 = 0x9E3779B9  # Q_w = odd((φ-1) * 2^w)
_MASK = 0xFFFFFFFF


# ---- 基本运算 ----

def _rotl32(x: int, n: int) -> int:
    n &= 31
    if n == 0:
        return x & _MASK
    return ((x << n) | (x >> (32 - n))) & _MASK


def _rotr32(x: int, n: int) -> int:
    n &= 31
    if n == 0:
        return x & _MASK
    return ((x >> n) | (x << (32 - n))) & _MASK


# ---- 密钥扩展 ----

def _key_expansion(key: bytes) -> list:
    """从 b 字节密钥生成 2r+4 个轮密钥。"""
    b = len(key)
    # 将密钥转换为 c 个 w/8 字节字 (little-endian)
    c = max(1, (b + 3) // 4)
    L = [0] * c
    for i in range(b):
        L[i // 4] |= key[i] << (8 * (i % 4))

    t = 2 * _R + 4
    S = [_P32]

    for i in range(1, t):
        S.append((S[i-1] + _Q32) & _MASK)

    A = 0
    B = 0
    i = 0
    j = 0
    v = 3 * max(t, c)

    for _ in range(v):
        A = S[i] = _rotl32((S[i] + A + B) & _MASK, 3)
        B = L[j] = _rotl32((L[j] + A + B) & _MASK, (A + B) & 31)
        i = (i + 1) % t
        j = (j + 1) % c

    return S


# ---- 加解密 ----

def _encrypt_block(block: bytes, S: list) -> bytes:
    """加密一个 16 字节分组。"""
    A, B, C, D = struct.unpack('<IIII', block)
    B = (B + S[0]) & _MASK
    D = (D + S[1]) & _MASK

    for i in range(1, _R + 1):
        t = _rotl32((B * (2 * B + 1)) & _MASK, 5)  # lgw = 5 for w=32
        u = _rotl32((D * (2 * D + 1)) & _MASK, 5)
        A = (_rotl32(A ^ t, u & 31) + S[2 * i]) & _MASK
        C = (_rotl32(C ^ u, t & 31) + S[2 * i + 1]) & _MASK
        A, B, C, D = B, C, D, A

    A = (A + S[2 * _R + 2]) & _MASK
    C = (C + S[2 * _R + 3]) & _MASK

    return struct.pack('<IIII', A, B, C, D)


def _decrypt_block(block: bytes, S: list) -> bytes:
    """解密一个 16 字节分组。"""
    A, B, C, D = struct.unpack('<IIII', block)

    C = (C - S[2 * _R + 3]) & _MASK
    A = (A - S[2 * _R + 2]) & _MASK

    for i in range(_R, 0, -1):
        # Undo the rotation: A,B,C,D was rotated left at end of encrypt
        A, B, C, D = D, A, B, C

        u = _rotl32((D * (2 * D + 1)) & _MASK, 5)
        t = _rotl32((B * (2 * B + 1)) & _MASK, 5)
        C = (_rotr32((C - S[2 * i + 1]) & _MASK, t & 31) ^ u)
        A = (_rotr32((A - S[2 * i]) & _MASK, u & 31) ^ t)

    D = (D - S[1]) & _MASK
    B = (B - S[0]) & _MASK

    return struct.pack('<IIII', A, B, C, D)


# ---- PKCS7 填充 ----

def _pkcs7_pad(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n] * n)


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise CryptoError(2001, "empty data after decryption")
    n = data[-1]
    if n < 1 or n > 16:
        raise CryptoError(2001, f"invalid PKCS7 padding value: {n}")
    if data[-n:] != bytes([n] * n):
        raise CryptoError(2001, "invalid PKCS7 padding")
    return data[:-n]


# ---- 外部接口 ----

def encrypt(data: bytes, key: bytes, mode: str = "ECB",
            iv: bytes = None, padding: str = "pkcs7",
            trace_collector: TraceCollector = None) -> bytes:
    if len(key) not in (16, 24, 32):
        raise CryptoError(1007, f"RC6 key must be 16/24/32 bytes, got {len(key)}")

    S = _key_expansion(key)

    if tc := trace_collector:
        tc.add_step("key_expansion", {
            "round_keys": len(S),
            "S_head": [hex(S[i]) for i in range(4)],
        })

    if padding == "pkcs7":
        data = _pkcs7_pad(data)
    elif padding == "none":
        if len(data) % 16 != 0:
            raise CryptoError(1004, "data length must be multiple of 16 with padding=none")
    else:
        raise CryptoError(1006, padding)

    result = bytearray()
    if mode.upper() == "ECB":
        for i in range(0, len(data), 16):
            result.extend(_encrypt_block(data[i:i+16], S))
    elif mode.upper() == "CBC":
        if iv is None:
            raise CryptoError(1008, "IV required for CBC mode")
        if len(iv) != 16:
            raise CryptoError(1008, f"RC6 IV must be 16 bytes, got {len(iv)}")
        prev = iv
        for i in range(0, len(data), 16):
            block = bytes(a ^ b for a, b in zip(data[i:i+16], prev))
            enc = _encrypt_block(block, S)
            result.extend(enc)
            prev = enc
    else:
        raise CryptoError(1006, f"unsupported RC6 mode: {mode}")

    return bytes(result)


def decrypt(data: bytes, key: bytes, mode: str = "ECB",
            iv: bytes = None, padding: str = "pkcs7",
            trace_collector: TraceCollector = None) -> bytes:
    if len(key) not in (16, 24, 32):
        raise CryptoError(1007, f"RC6 key must be 16/24/32 bytes, got {len(key)}")
    if len(data) % 16 != 0:
        raise CryptoError(1004, "ciphertext length must be multiple of 16")

    S = _key_expansion(key)

    result = bytearray()
    if mode.upper() == "ECB":
        for i in range(0, len(data), 16):
            result.extend(_decrypt_block(data[i:i+16], S))
    elif mode.upper() == "CBC":
        if iv is None:
            raise CryptoError(1008, "IV required for CBC mode")
        if len(iv) != 16:
            raise CryptoError(1008, f"RC6 IV must be 16 bytes, got {len(iv)}")
        prev = iv
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            dec = _decrypt_block(block, S)
            dec = bytes(a ^ b for a, b in zip(dec, prev))
            result.extend(dec)
            prev = block
    else:
        raise CryptoError(1006, f"unsupported RC6 mode: {mode}")

    if padding == "pkcs7":
        result = bytearray(_pkcs7_unpad(bytes(result)))

    return bytes(result)


# ---- API 接口 ----

def compute_encrypt(raw: str, key_raw: str, encoding: str = "hex",
                    key_encoding: str = "hex", mode: str = "ECB",
                    iv_raw: str = None, iv_encoding: str = "hex",
                    padding: str = "pkcs7", output: str = "hex",
                    trace: bool = False, trace_level: int = 1) -> dict:
    tc = TraceCollector(enabled=trace, level=trace_level)
    tc.set_meta(algorithm="RC6", operation="encrypt")

    with measure_time() as mt:
        data = parse_input(raw, encoding)
        key = parse_input(key_raw, key_encoding)
        iv = None
        if iv_raw is not None:
            iv = parse_input(iv_raw, iv_encoding)

        tc.add_step("input", TraceCollector.summarize_bytes(data))
        tc.add_step("key", TraceCollector.summarize_key(key))
        if iv:
            tc.add_step("iv", TraceCollector.summarize_key(iv))
        tc.add_step("params", {"mode": mode, "padding": padding})

        ct = encrypt(data, key, mode=mode, iv=iv, padding=padding,
                     trace_collector=tc if tc.level >= 2 else None)
        tc.add_step("output", TraceCollector.summarize_bytes(ct))

        result_str = format_output(ct, output)

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": {
            "ciphertext": result_str,
            "output_encoding": output,
        },
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }


def compute_decrypt(raw: str, key_raw: str, encoding: str = "hex",
                    key_encoding: str = "hex", mode: str = "ECB",
                    iv_raw: str = None, iv_encoding: str = "hex",
                    padding: str = "pkcs7", output: str = "hex",
                    trace: bool = False, trace_level: int = 1) -> dict:
    tc = TraceCollector(enabled=trace, level=trace_level)
    tc.set_meta(algorithm="RC6", operation="decrypt")

    with measure_time() as mt:
        data = parse_input(raw, encoding)
        key = parse_input(key_raw, key_encoding)
        iv = None
        if iv_raw is not None:
            iv = parse_input(iv_raw, iv_encoding)

        tc.add_step("input", TraceCollector.summarize_bytes(data))
        tc.add_step("key", TraceCollector.summarize_key(key))
        if iv:
            tc.add_step("iv", TraceCollector.summarize_key(iv))
        tc.add_step("params", {"mode": mode, "padding": padding})

        pt = decrypt(data, key, mode=mode, iv=iv, padding=padding,
                     trace_collector=tc if tc.level >= 2 else None)
        tc.add_step("output", TraceCollector.summarize_bytes(pt))

        result_str = format_output(pt, output)

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": {
            "plaintext": result_str,
            "output_encoding": output,
        },
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }
