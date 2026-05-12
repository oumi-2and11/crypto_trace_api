"""SM4 — 从零实现，含 Level 1 Trace。

参考：GB/T 32907-2016 《信息安全技术 SM4 分组密码算法》
- 128-bit 密钥，128-bit 分组
- 32 轮非线性迭代
- S-Box、系统参数 FK、固定参数 CK
"""

import struct
from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output
from utils.common.validation import CryptoError


# ---- S-Box (256 字节, GB/T 32907-2016) ----

_SBOX = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
]

# ---- 系统参数 FK ----

_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

# ---- 固定参数 CK ----

_CK = [
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279,
]

_MASK32 = 0xFFFFFFFF


# ---- 基本运算 ----

def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _tau(a: int) -> int:
    """非线性变换 τ：对 32-bit 字逐字节查 S-Box。"""
    return ((_SBOX[(a >> 24) & 0xFF] << 24) |
            (_SBOX[(a >> 16) & 0xFF] << 16) |
            (_SBOX[(a >> 8) & 0xFF] << 8) |
            _SBOX[a & 0xFF])


def _l_prime(b: int) -> int:
    """线性变换 L'：用于密钥扩展。"""
    return b ^ _rotl32(b, 13) ^ _rotl32(b, 23)


def _l(b: int) -> int:
    """线性变换 L：用于轮函数。"""
    return b ^ _rotl32(b, 2) ^ _rotl32(b, 10) ^ _rotl32(b, 18) ^ _rotl32(b, 24)


def _t(x: int) -> int:
    return _l(_tau(x))


def _t_prime(x: int) -> int:
    return _l_prime(_tau(x))


# ---- 密钥扩展 ----

def _key_expansion(key: bytes) -> list:
    """从 16 字节密钥生成 32 个轮密钥。"""
    mk = struct.unpack('>IIII', key)
    k = [mk[i] ^ _FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        rk_i = k[0] ^ _t_prime(k[1] ^ k[2] ^ k[3] ^ _CK[i])
        rk.append(rk_i)
        k = [k[1], k[2], k[3], rk_i]
    return rk


# ---- 加解密 ----

def _encrypt_block(block: bytes, rk: list) -> bytes:
    """加密一个 16 字节分组。"""
    x = list(struct.unpack('>IIII', block))
    for i in range(32):
        x0_new = x[0] ^ _t(x[1] ^ x[2] ^ x[3] ^ rk[i])
        x = [x[1], x[2], x[3], x0_new]
    y = [x[3], x[2], x[1], x[0]]
    return struct.pack('>IIII', *y)


def _decrypt_block(block: bytes, rk: list) -> bytes:
    """解密一个 16 字节分组（使用逆序轮密钥）。"""
    return _encrypt_block(block, rk[::-1])


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
    if len(key) != 16:
        raise CryptoError(1007, f"SM4 key must be 16 bytes, got {len(key)}")

    rk = _key_expansion(key)

    if tc := trace_collector:
        tc.add_step("key_expansion", {
            "round_keys": 32,
            "rk_head": [hex(rk[i]) for i in range(4)],
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
            result.extend(_encrypt_block(data[i:i+16], rk))
    elif mode.upper() == "CBC":
        if iv is None:
            raise CryptoError(1008, "IV required for CBC mode")
        if len(iv) != 16:
            raise CryptoError(1008, f"SM4 IV must be 16 bytes, got {len(iv)}")
        prev = iv
        for i in range(0, len(data), 16):
            block = bytes(a ^ b for a, b in zip(data[i:i+16], prev))
            enc = _encrypt_block(block, rk)
            result.extend(enc)
            prev = enc
    else:
        raise CryptoError(1006, f"unsupported SM4 mode: {mode}")

    return bytes(result)


def decrypt(data: bytes, key: bytes, mode: str = "ECB",
            iv: bytes = None, padding: str = "pkcs7",
            trace_collector: TraceCollector = None) -> bytes:
    if len(key) != 16:
        raise CryptoError(1007, f"SM4 key must be 16 bytes, got {len(key)}")
    if len(data) % 16 != 0:
        raise CryptoError(1004, "ciphertext length must be multiple of 16")

    rk = _key_expansion(key)

    result = bytearray()
    if mode.upper() == "ECB":
        for i in range(0, len(data), 16):
            result.extend(_decrypt_block(data[i:i+16], rk))
    elif mode.upper() == "CBC":
        if iv is None:
            raise CryptoError(1008, "IV required for CBC mode")
        if len(iv) != 16:
            raise CryptoError(1008, f"SM4 IV must be 16 bytes, got {len(iv)}")
        prev = iv
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            dec = _decrypt_block(block, rk)
            dec = bytes(a ^ b for a, b in zip(dec, prev))
            result.extend(dec)
            prev = block
    else:
        raise CryptoError(1006, f"unsupported SM4 mode: {mode}")

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
    tc.set_meta(algorithm="SM4", operation="encrypt")

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
    tc.set_meta(algorithm="SM4", operation="decrypt")

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
