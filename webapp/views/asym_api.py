"""公钥密码 API 端点：RSA、RSA-SHA1、ECC、ECDSA。"""

from flask import Blueprint
from webapp.api_response import handle_api_call, make_response
from utils.common.validation import CryptoError, validate_encoding, validate_output_encoding

asym_api_bp = Blueprint("asym_api", __name__, url_prefix="/api/asymmetric")


# ---- RSA ----

@asym_api_bp.route("/rsa/keygen", methods=["POST"])
@handle_api_call
def rsa_keygen(data):
    from utils.asymmetric.rsa import compute_keygen

    bits = data.get("bits", 1024)
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    return compute_keygen(bits=bits, trace=trace, trace_level=trace_level)


@asym_api_bp.route("/rsa/sign", methods=["POST"])
@handle_api_call
def rsa_sign(data):
    from utils.asymmetric.rsa import compute_sign

    raw = data.get("data", "")
    encoding = validate_encoding(data.get("encoding", "hex"))
    n_hex = data.get("n", "")
    d_hex = data.get("d", "")
    hash_algo = data.get("hash_algo", "sha256")
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    if not n_hex or not d_hex:
        raise CryptoError(1002, "n and d are required")

    return compute_sign(raw=raw, encoding=encoding, n_hex=n_hex, d_hex=d_hex,
                        hash_algo=hash_algo, output=output,
                        trace=trace, trace_level=trace_level)


@asym_api_bp.route("/rsa/verify", methods=["POST"])
@handle_api_call
def rsa_verify(data):
    from utils.asymmetric.rsa import compute_verify

    raw = data.get("data", "")
    encoding = validate_encoding(data.get("encoding", "hex"))
    signature_raw = data.get("signature", "")
    sig_encoding = validate_encoding(data.get("sig_encoding", "hex"))
    n_hex = data.get("n", "")
    e_hex = data.get("e", "65537")
    hash_algo = data.get("hash_algo", "sha256")
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    if not n_hex:
        raise CryptoError(1002, "n is required")

    return compute_verify(raw=raw, encoding=encoding, signature_raw=signature_raw,
                          sig_encoding=sig_encoding, n_hex=n_hex, e_hex=e_hex,
                          hash_algo=hash_algo, output=output,
                          trace=trace, trace_level=trace_level)


# ---- RSA-SHA1 ----

@asym_api_bp.route("/rsa-sha1/sign", methods=["POST"])
@handle_api_call
def rsa_sha1_sign(data):
    from utils.asymmetric.rsa_sha1 import compute_sign

    raw = data.get("data", "")
    encoding = validate_encoding(data.get("encoding", "hex"))
    n_hex = data.get("n", "")
    d_hex = data.get("d", "")
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    if not n_hex or not d_hex:
        raise CryptoError(1002, "n and d are required")

    return compute_sign(raw=raw, encoding=encoding, n_hex=n_hex, d_hex=d_hex,
                        output=output, trace=trace, trace_level=trace_level)


@asym_api_bp.route("/rsa-sha1/verify", methods=["POST"])
@handle_api_call
def rsa_sha1_verify(data):
    from utils.asymmetric.rsa_sha1 import compute_verify

    raw = data.get("data", "")
    encoding = validate_encoding(data.get("encoding", "hex"))
    signature_raw = data.get("signature", "")
    sig_encoding = validate_encoding(data.get("sig_encoding", "hex"))
    n_hex = data.get("n", "")
    e_hex = data.get("e", "65537")
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    if not n_hex:
        raise CryptoError(1002, "n is required")

    return compute_verify(raw=raw, encoding=encoding, signature_raw=signature_raw,
                          sig_encoding=sig_encoding, n_hex=n_hex, e_hex=e_hex,
                          output=output, trace=trace, trace_level=trace_level)


# ---- ECC ----

@asym_api_bp.route("/ecc/keygen", methods=["POST"])
@handle_api_call
def ecc_keygen(data):
    from utils.asymmetric.ecc import compute_keygen

    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    return compute_keygen(trace=trace, trace_level=trace_level)


# ---- ECDSA ----

@asym_api_bp.route("/ecdsa/sign", methods=["POST"])
@handle_api_call
def ecdsa_sign(data):
    from utils.asymmetric.ecdsa import compute_sign

    raw = data.get("data", "")
    encoding = validate_encoding(data.get("encoding", "hex"))
    private_key_hex = data.get("private_key", "")
    hash_algo = data.get("hash_algo", "sha256")
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    if not private_key_hex:
        raise CryptoError(1002, "private_key is required")

    return compute_sign(raw=raw, encoding=encoding, private_key_hex=private_key_hex,
                        hash_algo=hash_algo, output=output,
                        trace=trace, trace_level=trace_level)


@asym_api_bp.route("/ecdsa/verify", methods=["POST"])
@handle_api_call
def ecdsa_verify(data):
    from utils.asymmetric.ecdsa import compute_verify

    raw = data.get("data", "")
    encoding = validate_encoding(data.get("encoding", "hex"))
    r_hex = data.get("r", "")
    s_hex = data.get("s", "")
    pub_x_hex = data.get("pub_x", "")
    pub_y_hex = data.get("pub_y", "")
    hash_algo = data.get("hash_algo", "sha256")
    output = validate_output_encoding(data.get("output", "hex"))
    trace = data.get("trace", False)
    trace_level = data.get("trace_level", 1)

    if not r_hex or not s_hex or not pub_x_hex or not pub_y_hex:
        raise CryptoError(1002, "r, s, pub_x, pub_y are required")

    return compute_verify(raw=raw, encoding=encoding, r_hex=r_hex, s_hex=s_hex,
                          pub_x_hex=pub_x_hex, pub_y_hex=pub_y_hex,
                          hash_algo=hash_algo, output=output,
                          trace=trace, trace_level=trace_level)
