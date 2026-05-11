"""哈希类 API 端点：SHA-256 等。"""

from flask import Blueprint
from webapp.api_response import handle_api_call, make_response
from utils.common.validation import CryptoError, validate_encoding, validate_output_encoding

hash_api_bp = Blueprint("hash_api", __name__, url_prefix="/api/hash")

_SUPPORTED_ALGORITHMS = {"SHA256", "SHA-256"}

_NOT_IMPLEMENTED = {"SHA1", "SHA-1", "SHA3", "SHA-3", "RIPEMD160", "RIPEMD-160"}


@hash_api_bp.route("/digest", methods=["POST"])
@handle_api_call
def hash_digest(data):
    from utils.hash.sha256 import compute as sha256_compute

    algorithm = data.get("algorithm", "SHA256").upper().replace("-", "")
    raw = data.get("data", "")
    encoding = validate_encoding(data.get("encoding", "hex"))
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    # 标准化算法名
    algo_key = algorithm
    if algorithm in ("SHA256",):
        algo_key = "SHA256"

    if algo_key in ("SHA256",):
        return sha256_compute(raw, encoding=encoding, output=output,
                              trace=trace, trace_level=trace_level)

    if algorithm.replace("-", "") in ("SHA1", "SHA3", "RIPEMD160"):
        return make_response(9002, f"Algorithm {algorithm} not implemented yet")

    raise CryptoError(1005, algorithm)
