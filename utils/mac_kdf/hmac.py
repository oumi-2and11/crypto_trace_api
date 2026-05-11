"""HMAC — 从零实现（基于自写哈希），Level 1 Trace。

参考：RFC 2104
"""

from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.encoding import parse_input, format_output
from utils.common.validation import CryptoError

_BLOCK_SIZE = {
    "SHA1": 64, "SHA-1": 64,
    "SHA256": 64, "SHA-256": 64,
}

_HASH_FUNCS = {}


def _get_hash_func(algorithm: str):
    algo_key = algorithm.upper().replace("-", "")
    if algo_key in ("SHA1",):
        from utils.hash.sha1 import digest
        return digest, 20
    elif algo_key in ("SHA256",):
        from utils.hash.sha256 import digest
        return digest, 32
    else:
        raise CryptoError(1005, f"HMAC unsupported hash: {algorithm}")


def _hmac_compute(key: bytes, data: bytes, hash_algo: str = "SHA256",
                   tc: TraceCollector = None) -> bytes:
    hash_func, hash_len = _get_hash_func(hash_algo)
    block_size = 64

    # 密钥规范化
    if len(key) > block_size:
        key = hash_func(key)
    key = key.ljust(block_size, b'\x00')

    # ipad / opad
    o_key_pad = bytes(k ^ 0x5c for k in key)
    i_key_pad = bytes(k ^ 0x36 for k in key)

    if tc:
        tc.add_step("key_normalize", {"block_size": block_size, "key_len": len(key)})
        tc.add_step("ipad_opad", {
            "ipad_head": i_key_pad[:8].hex(),
            "opad_head": o_key_pad[:8].hex(),
        })

    # HMAC(K, m) = H(o_key_pad || H(i_key_pad || m))
    inner_hash = hash_func(i_key_pad + data)
    return hash_func(o_key_pad + inner_hash)


def compute(key_raw: str, data_raw: str, algorithm: str = "HmacSHA256",
            key_encoding: str = "hex", data_encoding: str = "hex",
            output: str = "hex", trace: bool = False,
            trace_level: int = 1) -> dict:
    tc = TraceCollector(enabled=trace, level=trace_level)

    # 解析算法名
    algo_name = algorithm.upper().replace("HMAC", "").replace("-", "")
    if algo_name == "SHA1":
        hash_algo = "SHA-1"
        tc.set_meta(algorithm="HMAC-SHA1", operation="compute")
    elif algo_name in ("SHA256",):
        hash_algo = "SHA-256"
        tc.set_meta(algorithm="HMAC-SHA256", operation="compute")
    else:
        raise CryptoError(1005, algorithm)

    with measure_time() as mt:
        key = parse_input(key_raw, key_encoding)
        data = parse_input(data_raw, data_encoding)
        tc.add_step("input", {
            "key": TraceCollector.summarize_key(key),
            "data": TraceCollector.summarize_bytes(data),
        })

        mac = _hmac_compute(key, data, hash_algo, tc)
        tc.add_step("output", TraceCollector.summarize_bytes(mac))

        result_str = format_output(mac, output)

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": {"mac": result_str, "output_encoding": output},
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }
