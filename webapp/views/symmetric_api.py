"""对称加密 API 端点：AES-128。"""

from flask import Blueprint
from webapp.api_response import handle_api_call, make_response
from utils.common.validation import CryptoError, validate_encoding, validate_output_encoding

symmetric_api_bp = Blueprint("symmetric_api", __name__, url_prefix="/api/symmetric")


@symmetric_api_bp.route("/aes/encrypt", methods=["POST"])
@handle_api_call
def aes_encrypt(data):
    from utils.symmetric.aes import compute_encrypt

    raw = data.get("data", "")
    key_raw = data.get("key", "")
    encoding = validate_encoding(data.get("encoding", "hex"))
    key_encoding = validate_encoding(data.get("key_encoding", "hex"))
    mode = data.get("mode", "ECB").upper()
    iv_raw = data.get("iv", None)
    iv_encoding = validate_encoding(data.get("iv_encoding", "hex")) if iv_raw else "hex"
    padding = data.get("padding", "pkcs7")
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    return compute_encrypt(
        raw=raw, key_raw=key_raw, encoding=encoding, key_encoding=key_encoding,
        mode=mode, iv_raw=iv_raw, iv_encoding=iv_encoding,
        padding=padding, output=output, trace=trace, trace_level=trace_level,
    )


@symmetric_api_bp.route("/aes/decrypt", methods=["POST"])
@handle_api_call
def aes_decrypt(data):
    from utils.symmetric.aes import compute_decrypt

    raw = data.get("data", "")
    key_raw = data.get("key", "")
    encoding = validate_encoding(data.get("encoding", "hex"))
    key_encoding = validate_encoding(data.get("key_encoding", "hex"))
    mode = data.get("mode", "ECB").upper()
    iv_raw = data.get("iv", None)
    iv_encoding = validate_encoding(data.get("iv_encoding", "hex")) if iv_raw else "hex"
    padding = data.get("padding", "pkcs7")
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    return compute_decrypt(
        raw=raw, key_raw=key_raw, encoding=encoding, key_encoding=key_encoding,
        mode=mode, iv_raw=iv_raw, iv_encoding=iv_encoding,
        padding=padding, output=output, trace=trace, trace_level=trace_level,
    )


@symmetric_api_bp.route("/sm4/encrypt", methods=["POST"])
@handle_api_call
def sm4_encrypt(data):
    return make_response(9002, "SM4 not implemented yet")


@symmetric_api_bp.route("/sm4/decrypt", methods=["POST"])
@handle_api_call
def sm4_decrypt(data):
    return make_response(9002, "SM4 not implemented yet")


@symmetric_api_bp.route("/rc6/encrypt", methods=["POST"])
@handle_api_call
def rc6_encrypt(data):
    return make_response(9002, "RC6 not implemented yet")


@symmetric_api_bp.route("/rc6/decrypt", methods=["POST"])
@handle_api_call
def rc6_decrypt(data):
    return make_response(9002, "RC6 not implemented yet")
