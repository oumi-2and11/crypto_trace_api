"""统一编解码工具：hex / base64 / text(utf-8) 与 bytes 互转。"""

import re


def hex_to_bytes(hex_str: str) -> bytes:
    if not isinstance(hex_str, str):
        raise ValueError("hex input must be a string")
    hex_str = hex_str.strip()
    if not re.fullmatch(r'[0-9a-fA-F]*', hex_str):
        raise ValueError("invalid hex character")
    if len(hex_str) % 2 != 0:
        raise ValueError("hex string must have even length")
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


# ---- Base64 (自实现，不依赖 Python 内置 base64) ----

_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_DECODE_MAP = {c: i for i, c in enumerate(_B64_ALPHABET)}


def base64_to_bytes(b64_str: str) -> bytes:
    s = b64_str.strip()
    padding = s.count('=')
    s = s.rstrip('=')
    if not re.fullmatch(r'[A-Za-z0-9+/]*', s):
        raise ValueError("invalid Base64 character")
    if padding > 2:
        raise ValueError("invalid Base64 padding")
    buf = 0
    bits = 0
    out = bytearray()
    for c in s:
        if c not in _B64_DECODE_MAP:
            raise ValueError(f"invalid Base64 character: {c!r}")
        buf = (buf << 6) | _B64_DECODE_MAP[c]
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
    return bytes(out)


def bytes_to_base64(data: bytes) -> str:
    if not data:
        return ""
    out = []
    buf = 0
    bits = 0
    for byte in data:
        buf = (buf << 8) | byte
        bits += 8
        while bits >= 6:
            bits -= 6
            out.append(_B64_ALPHABET[(buf >> bits) & 0x3F])
    if bits > 0:
        out.append(_B64_ALPHABET[(buf << (6 - bits)) & 0x3F])
    remainder = len(data) % 3
    if remainder == 1:
        out.append("==")
    elif remainder == 2:
        out.append("=")
    return "".join(out)


# ---- UTF-8 (自实现) ----

def text_to_bytes(text: str) -> bytes:
    out = bytearray()
    for char in text:
        cp = ord(char)
        if cp <= 0x7F:
            out.append(cp)
        elif cp <= 0x7FF:
            out.append(0xC0 | (cp >> 6))
            out.append(0x80 | (cp & 0x3F))
        elif cp <= 0xFFFF:
            out.append(0xE0 | (cp >> 12))
            out.append(0x80 | ((cp >> 6) & 0x3F))
            out.append(0x80 | (cp & 0x3F))
        elif cp <= 0x10FFFF:
            out.append(0xF0 | (cp >> 18))
            out.append(0x80 | ((cp >> 12) & 0x3F))
            out.append(0x80 | ((cp >> 6) & 0x3F))
            out.append(0x80 | (cp & 0x3F))
        else:
            raise ValueError(f"code point {cp} out of Unicode range")
    return bytes(out)


def bytes_to_text(data: bytes) -> str:
    i = 0
    out = []
    n = len(data)
    while i < n:
        b0 = data[i]
        if b0 <= 0x7F:
            out.append(chr(b0))
            i += 1
        elif 0xC2 <= b0 <= 0xDF:
            if i + 1 >= n:
                raise ValueError("truncated UTF-8 sequence")
            b1 = data[i + 1]
            if (b1 & 0xC0) != 0x80:
                raise ValueError("invalid UTF-8 continuation byte")
            cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F)
            out.append(chr(cp))
            i += 2
        elif 0xE0 <= b0 <= 0xEF:
            if i + 2 >= n:
                raise ValueError("truncated UTF-8 sequence")
            b1, b2 = data[i + 1], data[i + 2]
            if (b1 & 0xC0) != 0x80 or (b2 & 0xC0) != 0x80:
                raise ValueError("invalid UTF-8 continuation byte")
            cp = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F)
            if cp < 0x800 or (0xD800 <= cp <= 0xDFFF):
                raise ValueError("invalid UTF-8 code point")
            out.append(chr(cp))
            i += 3
        elif 0xF0 <= b0 <= 0xF4:
            if i + 3 >= n:
                raise ValueError("truncated UTF-8 sequence")
            b1, b2, b3 = data[i + 1], data[i + 2], data[i + 3]
            if (b1 & 0xC0) != 0x80 or (b2 & 0xC0) != 0x80 or (b3 & 0xC0) != 0x80:
                raise ValueError("invalid UTF-8 continuation byte")
            cp = ((b0 & 0x07) << 18) | ((b1 & 0x3F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)
            if cp < 0x10000 or cp > 0x10FFFF:
                raise ValueError("invalid UTF-8 code point")
            out.append(chr(cp))
            i += 4
        else:
            raise ValueError(f"invalid UTF-8 start byte: 0x{b0:02X}")
    return "".join(out)


# ---- 统一输入输出路由 ----

def parse_input(raw: str, encoding: str) -> bytes:
    encoding = encoding.lower()
    if encoding == "hex":
        return hex_to_bytes(raw)
    elif encoding == "base64":
        return base64_to_bytes(raw)
    elif encoding == "text":
        return text_to_bytes(raw)
    else:
        raise ValueError(f"unsupported encoding: {encoding!r}")


def format_output(data: bytes, encoding: str) -> str:
    encoding = encoding.lower()
    if encoding == "hex":
        return bytes_to_hex(data)
    elif encoding == "base64":
        return bytes_to_base64(data)
    elif encoding == "text":
        return bytes_to_text(data)
    else:
        raise ValueError(f"unsupported output encoding: {encoding!r}")
