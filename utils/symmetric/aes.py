"""AES-128 — 从零实现，含 Level 2 Trace（轮密钥/轮状态采样）。

参考：FIPS 197
"""

import struct
from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output
from utils.common.validation import CryptoError

# ---- S-Box 与 InvS-Box ----

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

_INV_SBOX = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
]

# ---- Galois 域乘法 ----

def _xtime(a: int) -> int:
    return ((a << 1) ^ (0x1b if a & 0x80 else 0)) & 0xFF

def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p

# ---- 轮常量 ----

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# ---- 密钥扩展 ----

def _key_expansion(key: bytes) -> list:
    assert len(key) == 16
    w = []
    for i in range(4):
        w.append(list(key[4*i:4*i+4]))

    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for r in range(11):
        rk = []
        for j in range(4):
            rk.extend(w[r * 4 + j])
        round_keys.append(bytes(rk))
    return round_keys

# ---- 状态矩阵操作 ----

def _bytes_to_state(data: bytes) -> list:
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state

def _state_to_bytes(state: list) -> bytes:
    out = bytearray(16)
    for i in range(16):
        out[i] = state[i % 4][i // 4]
    return bytes(out)

# ---- 轮函数 ----

def _sub_bytes(state: list) -> list:
    return [[_SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def _inv_sub_bytes(state: list) -> list:
    return [[_INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def _shift_rows(state: list) -> list:
    s = [row[:] for row in state]
    s[1] = s[1][1:] + s[1][:1]
    s[2] = s[2][2:] + s[2][:2]
    s[3] = s[3][3:] + s[3][:3]
    return s

def _inv_shift_rows(state: list) -> list:
    s = [row[:] for row in state]
    s[1] = s[1][3:] + s[1][:3]
    s[2] = s[2][2:] + s[2][:2]
    s[3] = s[3][1:] + s[3][:1]
    return s

def _mix_columns(state: list) -> list:
    s = [row[:] for row in state]
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        s[0][c] = _gf_mul(2, a[0]) ^ _gf_mul(3, a[1]) ^ a[2] ^ a[3]
        s[1][c] = a[0] ^ _gf_mul(2, a[1]) ^ _gf_mul(3, a[2]) ^ a[3]
        s[2][c] = a[0] ^ a[1] ^ _gf_mul(2, a[2]) ^ _gf_mul(3, a[3])
        s[3][c] = _gf_mul(3, a[0]) ^ a[1] ^ a[2] ^ _gf_mul(2, a[3])
    return s

def _inv_mix_columns(state: list) -> list:
    s = [row[:] for row in state]
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        s[0][c] = _gf_mul(14, a[0]) ^ _gf_mul(11, a[1]) ^ _gf_mul(13, a[2]) ^ _gf_mul(9, a[3])
        s[1][c] = _gf_mul(9, a[0]) ^ _gf_mul(14, a[1]) ^ _gf_mul(11, a[2]) ^ _gf_mul(13, a[3])
        s[2][c] = _gf_mul(13, a[0]) ^ _gf_mul(9, a[1]) ^ _gf_mul(14, a[2]) ^ _gf_mul(11, a[3])
        s[3][c] = _gf_mul(11, a[0]) ^ _gf_mul(13, a[1]) ^ _gf_mul(9, a[2]) ^ _gf_mul(14, a[3])
    return s

def _add_round_key(state: list, round_key: bytes) -> list:
    rk = _bytes_to_state(round_key)
    return [[state[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]

# ---- PKCS7 填充 ----

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise CryptoError(2001, "invalid ciphertext length for PKCS7 unpad")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise CryptoError(2001, "invalid PKCS7 padding value")
    for i in range(pad_len):
        if data[-(i+1)] != pad_len:
            raise CryptoError(2001, "invalid PKCS7 padding")
    return data[:-pad_len]

# ---- XOR ----

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# ---- 加密单块 ----

def _encrypt_block(plaintext: bytes, round_keys: list,
                    tc: TraceCollector = None, block_idx: int = 0) -> bytes:
    state = _bytes_to_state(plaintext)
    state = _add_round_key(state, round_keys[0])

    if tc and tc.level >= 2 and block_idx == 0:
        tc.add_step("key_expansion", {
            "round_keys_head": [rk[:8].hex() for rk in round_keys[:3]],
        })

    for rnd in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])

        if tc and tc.level >= 2 and block_idx == 0 and rnd in (1, 5, 9):
            tc.add_step("round_state_sample", {
                "block": block_idx, "round": rnd,
                "state_hex": _state_to_bytes(state).hex(),
            })

    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[10])

    if tc and tc.level >= 2 and block_idx == 0:
        tc.add_step("round_state_sample", {
            "block": block_idx, "round": 10,
            "state_hex": _state_to_bytes(state).hex(),
        })

    return _state_to_bytes(state)

# ---- 解密单块 ----

def _decrypt_block(ciphertext: bytes, round_keys: list) -> bytes:
    state = _bytes_to_state(ciphertext)
    state = _add_round_key(state, round_keys[10])

    for rnd in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[rnd])
        state = _inv_mix_columns(state)

    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)

# ---- 公开接口 ----

def encrypt(plaintext: bytes, key: bytes, mode: str = "ECB",
            iv: bytes = None, padding: str = "pkcs7",
            trace_collector: TraceCollector = None) -> bytes:
    if len(key) != 16:
        raise CryptoError(1007, f"AES-128 key must be 16 bytes, got {len(key)}")

    mode = mode.upper()
    if mode not in ("ECB", "CBC"):
        raise CryptoError(1006, f"unsupported mode: {mode}")
    if mode == "CBC":
        if iv is None or len(iv) != 16:
            raise CryptoError(1008, "CBC mode requires 16-byte IV")

    if padding == "pkcs7":
        plaintext = _pkcs7_pad(plaintext)
    elif padding != "none":
        raise CryptoError(1006, f"unsupported padding: {padding}")

    if len(plaintext) == 0 or len(plaintext) % 16 != 0:
        raise CryptoError(1004, "plaintext length must be multiple of 16 after padding")

    round_keys = _key_expansion(key)
    ciphertext = bytearray()
    prev = iv or b'\x00' * 16

    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        if mode == "CBC":
            block = _xor_bytes(block, prev)
        enc = _encrypt_block(block, round_keys, trace_collector, block_idx=i//16)
        ciphertext.extend(enc)
        prev = enc

    return bytes(ciphertext)


def decrypt(ciphertext: bytes, key: bytes, mode: str = "ECB",
            iv: bytes = None, padding: str = "pkcs7",
            trace_collector: TraceCollector = None) -> bytes:
    if len(key) != 16:
        raise CryptoError(1007, f"AES-128 key must be 16 bytes, got {len(key)}")
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise CryptoError(2001, "ciphertext length must be multiple of 16")

    mode = mode.upper()
    if mode not in ("ECB", "CBC"):
        raise CryptoError(1006, f"unsupported mode: {mode}")
    if mode == "CBC":
        if iv is None or len(iv) != 16:
            raise CryptoError(1008, "CBC mode requires 16-byte IV")

    round_keys = _key_expansion(key)
    plaintext = bytearray()
    prev = iv or b'\x00' * 16

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = _decrypt_block(block, round_keys)
        if mode == "CBC":
            dec = _xor_bytes(dec, prev)
        plaintext.extend(dec)
        prev = block

    if padding == "pkcs7":
        plaintext = bytearray(_pkcs7_unpad(bytes(plaintext)))

    return bytes(plaintext)


def compute_encrypt(raw: str, key_raw: str, encoding: str = "hex",
                    key_encoding: str = "hex", mode: str = "ECB",
                    iv_raw: str = None, iv_encoding: str = "hex",
                    padding: str = "pkcs7", output: str = "hex",
                    trace: bool = False, trace_level: int = 1) -> dict:
    tc = TraceCollector(enabled=trace, level=trace_level)
    tc.set_meta(algorithm="AES-128", operation="encrypt")

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

        ct = encrypt(data, key, mode=mode, iv=iv, padding=padding, trace_collector=tc)
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
    tc.set_meta(algorithm="AES-128", operation="decrypt")

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

        pt = decrypt(data, key, mode=mode, iv=iv, padding=padding, trace_collector=tc)
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
