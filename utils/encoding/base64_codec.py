"""Base64 编解码 — 从零实现，不依赖 Python 内置 base64 模块。"""

from utils.common.encoding import (
    base64_to_bytes, bytes_to_base64,
    parse_input, format_output,
)
from utils.common.trace import TraceCollector
from utils.common.timing import measure_time


def encode(raw: str, encoding: str = "text", output: str = "text",
           trace: bool = False, trace_level: int = 1) -> dict:
    """Base64 编码。

    Args:
        raw: 输入数据字符串
        encoding: 输入编码 (hex/base64/text)
        output: 输出编码 (hex/base64/text)
        trace: 是否开启 trace
        trace_level: trace 级别

    Returns:
        dict: {"result": {"base64": ..., "output_encoding": ...}, "trace": ..., "time_ms": ...}
    """
    tc = TraceCollector(enabled=trace, level=trace_level)
    tc.set_meta(algorithm="Base64", operation="encode")

    with measure_time() as mt:
        data_bytes = parse_input(raw, encoding)
        tc.add_step("input_bytes", {"len": len(data_bytes), "hex": data_bytes[:32].hex()})

        # 分组信息
        full_groups = len(data_bytes) // 3
        remainder = len(data_bytes) % 3
        tc.add_step("groups_3bytes", {"count": full_groups + (1 if remainder else 0),
                                       "remainder_bytes": remainder})

        encoded = bytes_to_base64(data_bytes)
        tc.add_step("output", {"len": len(encoded), "head": encoded[:32]})

    result_str = encoded
    if output == "hex":
        result_str = parse_input(encoded, "text").hex()
    elif output == "base64":
        pass  # already base64

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": {
            "base64": result_str,
            "output_encoding": output,
        },
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }


def decode(raw: str, encoding: str = "text", output: str = "text",
           trace: bool = False, trace_level: int = 1) -> dict:
    """Base64 解码。"""
    from utils.common.validation import CryptoError

    tc = TraceCollector(enabled=trace, level=trace_level)
    tc.set_meta(algorithm="Base64", operation="decode")

    with measure_time() as mt:
        if encoding == "text":
            b64_str = raw
        elif encoding == "hex":
            # hex 编码的 base64 字符串 → 先 hex 解码得到 base64 字符串
            from utils.common.encoding import hex_to_bytes
            b64_str = hex_to_bytes(raw).decode("ascii")
        elif encoding == "base64":
            b64_str = raw
        else:
            raise CryptoError(1009, encoding)

        tc.add_step("input_b64", {"len": len(b64_str), "head": b64_str[:32]})

        try:
            decoded = base64_to_bytes(b64_str)
        except ValueError as e:
            raise CryptoError(3002, str(e))

        tc.add_step("output_bytes", {"len": len(decoded), "hex": decoded[:32].hex()})

        result_str = format_output(decoded, output)

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": {
            "data": result_str,
            "output_encoding": output,
        },
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }
