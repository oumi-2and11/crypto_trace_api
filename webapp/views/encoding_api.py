"""编码类 API 端点：Base64 / UTF-8。"""

from flask import Blueprint
from webapp.api_response import handle_api_call, make_response
from utils.common.validation import CryptoError, validate_encoding, validate_output_encoding, require_fields

encoding_api_bp = Blueprint("encoding_api", __name__, url_prefix="/api/encoding")


@encoding_api_bp.route("/base64/encode", methods=["POST"])
@handle_api_call
def base64_encode(data):
    from utils.encoding.base64_codec import encode as b64_encode

    raw = data.get("data", "")
    encoding = validate_encoding(data.get("encoding", "text"))
    output = validate_output_encoding(data.get("output", "text"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    return b64_encode(raw, encoding=encoding, output=output, trace=trace, trace_level=trace_level)


@encoding_api_bp.route("/base64/decode", methods=["POST"])
@handle_api_call
def base64_decode(data):
    from utils.encoding.base64_codec import decode as b64_decode

    raw = data.get("data", "")
    encoding = validate_encoding(data.get("encoding", "text"))
    output = validate_output_encoding(data.get("output", "text"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    return b64_decode(raw, encoding=encoding, output=output, trace=trace, trace_level=trace_level)


@encoding_api_bp.route("/utf8/encode", methods=["POST"])
@handle_api_call
def utf8_encode(data):
    from utils.encoding.utf8_codec import encode as u8_encode

    text = data.get("text", "")
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    return u8_encode(text, output=output, trace=trace, trace_level=trace_level)


@encoding_api_bp.route("/utf8/decode", methods=["POST"])
@handle_api_call
def utf8_decode(data):
    from utils.encoding.utf8_codec import decode as u8_decode

    raw = data.get("data", "")
    encoding = validate_encoding(data.get("encoding", "hex"))
    output = validate_output_encoding(data.get("output", "text"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    return u8_decode(raw, encoding=encoding, output=output, trace=trace, trace_level=trace_level)
