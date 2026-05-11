"""参数校验与状态码映射。"""

STATUS_CODES = {
    0: "OK",

    # 参数错误 1xxx
    1001: "Invalid JSON",
    1002: "Missing required field",
    1003: "Invalid field type",
    1004: "Invalid value / out of range",
    1005: "Unsupported algorithm",
    1006: "Unsupported mode/padding",
    1007: "Invalid key length",
    1008: "Invalid iv/nonce length",
    1009: "Invalid encoding",
    1010: "Invalid output encoding",
    1011: "Trace level not supported",

    # 算法执行错误 2xxx
    2001: "Decrypt failed",
    2002: "Verify failed",
    2003: "Invalid signature format",
    2004: "RSA key invalid",
    2005: "RSA keygen failed",
    2006: "ECC invalid curve params",
    2007: "ECC point not on curve",
    2008: "ECC scalar out of range",
    2009: "Mod inverse not exist",
    2010: "PBKDF2 iterations too large",

    # 编码解码错误 3xxx
    3001: "Hex decode error",
    3002: "Base64 decode error",
    3003: "UTF-8 decode error",
    3004: "Text encode error",

    # 系统错误 9xxx
    9001: "Internal error",
    9002: "Not implemented",
    9003: "Timeout",
}


class CryptoError(Exception):
    def __init__(self, status_code: int, detail: str = ""):
        self.status_code = status_code
        base_msg = STATUS_CODES.get(status_code, "Unknown error")
        self.status_message = f"{base_msg}: {detail}" if detail else base_msg
        super().__init__(self.status_message)


def validate_encoding(encoding: str) -> str:
    encoding = (encoding or "hex").lower()
    if encoding not in ("hex", "base64", "text"):
        raise CryptoError(1009, encoding)
    return encoding


def validate_output_encoding(output: str) -> str:
    output = (output or "hex").lower()
    if output not in ("hex", "base64", "text"):
        raise CryptoError(1010, output)
    return output


def require_fields(data: dict, fields: list):
    for f in fields:
        if f not in data or data[f] is None:
            raise CryptoError(1002, f)
