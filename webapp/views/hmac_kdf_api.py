"""HMAC 和 PBKDF2 API 端点。"""

from flask import Blueprint
from webapp.api_response import handle_api_call
from utils.common.validation import validate_encoding, validate_output_encoding

hmac_kdf_api_bp = Blueprint("hmac_kdf_api", __name__, url_prefix="/api")


@hmac_kdf_api_bp.route("/hmac/compute", methods=["POST"])
@handle_api_call
def hmac_compute(data):
    from utils.mac_kdf.hmac import compute as hmac_compute_func

    algorithm = data.get("algorithm", "HmacSHA256")
    key_raw = data.get("key", "")
    data_raw = data.get("data", "")
    key_encoding = validate_encoding(data.get("key_encoding", "hex"))
    data_encoding = validate_encoding(data.get("data_encoding", "hex"))
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    return hmac_compute_func(
        key_raw=key_raw, data_raw=data_raw, algorithm=algorithm,
        key_encoding=key_encoding, data_encoding=data_encoding,
        output=output, trace=trace, trace_level=trace_level,
    )


@hmac_kdf_api_bp.route("/kdf/pbkdf2", methods=["POST"])
@handle_api_call
def pbkdf2_derive(data):
    from utils.mac_kdf.pbkdf2 import compute as pbkdf2_compute

    prf = data.get("prf", "HmacSHA256")
    password_raw = data.get("password", "")
    salt_raw = data.get("salt", "")
    iterations = data.get("iterations", 1000)
    dk_len = data.get("dk_len", 32)
    password_encoding = validate_encoding(data.get("password_encoding", "hex"))
    salt_encoding = validate_encoding(data.get("salt_encoding", "hex"))
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    return pbkdf2_compute(
        password_raw=password_raw, salt_raw=salt_raw,
        iterations=iterations, dk_len=dk_len, prf=prf,
        password_encoding=password_encoding, salt_encoding=salt_encoding,
        output=output, trace=trace, trace_level=trace_level,
    )
