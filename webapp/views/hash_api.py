"""哈希类 API 端点：SHA-1/256/3/RIPEMD-160。"""

from flask import Blueprint
from webapp.api_response import handle_api_call, make_response
from utils.common.validation import CryptoError, validate_encoding, validate_output_encoding

hash_api_bp = Blueprint("hash_api", __name__, url_prefix="/api/hash")


@hash_api_bp.route("/digest", methods=["POST"])
@handle_api_call
def hash_digest(data):
    algorithm = data.get("algorithm", "SHA256").upper()
    raw = data.get("data", "")
    encoding = validate_encoding(data.get("encoding", "hex"))
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    algo_key = algorithm.replace("-", "").replace(" ", "")

    if algo_key in ("SHA256",):
        from utils.hash.sha256 import compute as sha256_compute
        return sha256_compute(raw, encoding=encoding, output=output,
                              trace=trace, trace_level=trace_level)

    if algo_key in ("SHA1",):
        from utils.hash.sha1 import compute as sha1_compute
        return sha1_compute(raw, encoding=encoding, output=output,
                            trace=trace, trace_level=trace_level)

    if algo_key in ("SHA3", "SHA3256"):
        from utils.hash.sha3 import compute as sha3_compute
        return sha3_compute(raw, encoding=encoding, output=output,
                            trace=trace, trace_level=trace_level)

    if algo_key in ("RIPEMD160",):
        from utils.hash.ripemd160 import compute as ripemd_compute
        return ripemd_compute(raw, encoding=encoding, output=output,
                              trace=trace, trace_level=trace_level)

    raise CryptoError(1005, algorithm)
