"""UTF-8 编解码 — 从零实现。"""

from utils.common.encoding import (
    text_to_bytes, bytes_to_text,
    hex_to_bytes, bytes_to_hex,
    parse_input, format_output,
)
from utils.common.trace import TraceCollector
from utils.common.timing import measure_time
from utils.common.validation import CryptoError


def encode(text: str, output: str = "hex", trace: bool = False,
           trace_level: int = 1) -> dict:
    """UTF-8 编码：字符串 → UTF-8 字节序列。"""
    tc = TraceCollector(enabled=trace, level=trace_level)
    tc.set_meta(algorithm="UTF-8", operation="encode")

    with measure_time() as mt:
        data_bytes = text_to_bytes(text)
        tc.add_step("input_text", {"len": len(text), "chars": len(text)})
        tc.add_step("output_bytes", {"len": len(data_bytes), "hex": data_bytes[:32].hex()})

        # 逐字符 UTF-8 编码详情
        if trace and trace_level >= 2:
            char_details = []
            for ch in text[:20]:
                cp = ord(ch)
                b = text_to_bytes(ch)
                char_details.append({
                    "char": ch,
                    "code_point": f"U+{cp:04X}",
                    "utf8_hex": b.hex(),
                    "byte_count": len(b),
                })
            tc.add_step("char_encoding_detail", {"chars": char_details})

        result_str = format_output(data_bytes, output)

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": {
            "data": result_str,
            "output_encoding": output,
            "byte_length": len(data_bytes),
        },
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }


def decode(raw: str, encoding: str = "hex", output: str = "text",
           trace: bool = False, trace_level: int = 1) -> dict:
    """UTF-8 解码：字节序列 → 字符串。"""
    tc = TraceCollector(enabled=trace, level=trace_level)
    tc.set_meta(algorithm="UTF-8", operation="decode")

    with measure_time() as mt:
        data_bytes = parse_input(raw, encoding)
        tc.add_step("input_bytes", {"len": len(data_bytes), "hex": data_bytes[:32].hex()})

        try:
            text = bytes_to_text(data_bytes)
        except ValueError as e:
            raise CryptoError(3003, str(e))

        tc.add_step("output_text", {"len": len(text), "chars": len(text)})

        result_str = format_output(data_bytes, output)
        if output == "text":
            result_str = text

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": {
            "data": result_str,
            "output_encoding": output,
            "char_count": len(text),
        },
        "trace": tc.to_dict(),
        "time_ms": mt.time_ms,
    }
