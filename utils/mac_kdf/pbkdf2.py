"""PBKDF2 — 从零实现（基于自写 HMAC），Level 1 Trace。

参考：RFC 8018 (PKCS #5)
"""

from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output
from utils.common.validation import CryptoError


def _hmac_raw(key: bytes, data: bytes, hash_algo: str = "SHA256") -> bytes:
    from utils.mac_kdf.hmac import _hmac_compute
    return _hmac_compute(key, data, hash_algo)


def _pbkdf2_derive(password: bytes, salt: bytes, iterations: int,
                    dk_len: int, hash_algo: str = "SHA256",
                    tc: TraceCollector = None) -> bytes:
    hash_len_map = {"SHA-1": 20, "SHA-256": 32}
    hash_len = hash_len_map.get(hash_algo, 32)
    n_blocks = (dk_len + hash_len - 1) // hash_len

    dk = b''
    for block_idx in range(1, n_blocks + 1):
        # U1 = HMAC(password, salt || INT_32_BE(block_idx))
        u = _hmac_raw(password, salt + block_idx.to_bytes(4, 'big'), hash_algo)
        result = u

        for i in range(2, iterations + 1):
            u = _hmac_raw(password, u, hash_algo)
            result = bytes(a ^ b for a, b in zip(result, u))

        dk += result

        if tc and block_idx <= 2:
            tc.add_step("block_compute", {
                "block_index": block_idx,
                "iterations": iterations,
            })

    return dk[:dk_len]


def compute(password_raw: str, salt_raw: str, iterations: int = 1000,
            dk_len: int = 32, prf: str = "HmacSHA256",
            password_encoding: str = "hex", salt_encoding: str = "hex",
            output: str = "hex", trace: bool = False,
            trace_level: int = 1) -> dict:
    tc = TraceCollector(enabled=trace, level=trace_level)

    prf_name = prf.upper().replace("HMAC", "").replace("-", "")
    if prf_name == "SHA1":
        hash_algo = "SHA-1"
        tc.set_meta(algorithm="PBKDF2-HMAC-SHA1", operation="derive")
    elif prf_name in ("SHA256",):
        hash_algo = "SHA-256"
        tc.set_meta(algorithm="PBKDF2-HMAC-SHA256", operation="derive")
    else:
        raise CryptoError(1005, prf)

    if iterations <= 0:
        raise CryptoError(1004, "iterations must be positive")
    if dk_len <= 0:
        raise CryptoError(1004, "dk_len must be positive")

    with measure_time() as mt:
        password = parse_input(password_raw, password_encoding)
        salt = parse_input(salt_raw, salt_encoding)
        tc.add_step("input", {
            "password_len": len(password),
            "salt": TraceCollector.summarize_bytes(salt),
        })
        tc.add_step("params", {
            "iterations": iterations,
            "dk_len": dk_len,
            "prf": hash_algo,
        })

        derived = _pbkdf2_derive(password, salt, iterations, dk_len, hash_algo, tc)
        tc.add_step("output", TraceCollector.summarize_bytes(derived))

        result_str = format_output(derived, output)

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": {
            "derived_key": result_str,
            "output_encoding": output,
            "iterations": iterations,
            "dk_len": dk_len,
        },
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }
