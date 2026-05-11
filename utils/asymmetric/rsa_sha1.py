"""RSA-SHA1 签名 — 基于自写 SHA-1 + RSA，含 Level 2 Trace。

参考：PKCS#1 v1.5 签名方案 (RFC 8017 §9.2)
"""

from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output
from utils.common.validation import CryptoError


def compute_sign(raw: str, encoding: str, n_hex: str, d_hex: str,
                  output: str = "hex",
                  trace: bool = False, trace_level: int = 1) -> dict:
    """RSA-SHA1 签名 API。"""
    from utils.asymmetric.rsa import _sign_internal

    tc = TraceCollector(enabled=trace, level=trace_level)
    with measure_time() as mt:
        tc.set_meta(algorithm="RSA-SHA1", operation="sign",
                    input_summary=TraceCollector.summarize_bytes(
                        parse_input(raw, encoding) if raw else b'', 16))

        message = parse_input(raw, encoding)
        n = int(n_hex, 16)
        d = int(d_hex, 16)

        if tc.level >= 2:
            tc.add_step("rsa_sha1_params", {
                "hash_algo": "sha1",
                "n_bits": n.bit_length(),
                "d_bits": d.bit_length(),
            })

        sig = _sign_internal(message, n, d, "sha1", tc)
        sig_str = format_output(sig, output)

        result = {"signature": sig_str}

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": result,
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }


def compute_verify(raw: str, encoding: str, signature_raw: str,
                    sig_encoding: str, n_hex: str, e_hex: str,
                    output: str = "hex",
                    trace: bool = False, trace_level: int = 1) -> dict:
    """RSA-SHA1 验签 API。"""
    from utils.asymmetric.rsa import _verify_internal

    tc = TraceCollector(enabled=trace, level=trace_level)
    with measure_time() as mt:
        tc.set_meta(algorithm="RSA-SHA1", operation="verify")

        message = parse_input(raw, encoding)
        sig_bytes = parse_input(signature_raw, sig_encoding)
        n = int(n_hex, 16)

        if e_hex.startswith("0x") or e_hex.startswith("0X"):
            e = int(e_hex, 16)
        else:
            try:
                e = int(e_hex)
            except ValueError:
                e = int(e_hex, 16)

        if tc.level >= 2:
            tc.add_step("rsa_sha1_verify_params", {
                "hash_algo": "sha1",
                "n_bits": n.bit_length(),
                "e": e,
            })

        valid = _verify_internal(message, sig_bytes, n, e, "sha1", tc)

        result = {"valid": valid}

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": result,
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }
