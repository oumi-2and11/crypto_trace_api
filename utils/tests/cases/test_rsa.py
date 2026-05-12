"""RSA 测试。"""

from utils.asymmetric.rsa import compute_keygen, compute_sign, compute_verify


def test_rsa_sign_verify():
    kg = compute_keygen(bits=512)
    n, e, d = kg["result"]["n"], kg["result"]["e"], kg["result"]["d"]

    sig = compute_sign(raw="68656c6c6f", encoding="hex", n_hex=n, d_hex=d, hash_algo="sha256")
    assert sig["status_code"] == 0
    assert len(sig["result"]["signature"]) > 0

    ver = compute_verify(raw="68656c6c6f", encoding="hex", signature_raw=sig["result"]["signature"],
                         sig_encoding="hex", n_hex=n, e_hex=e, hash_algo="sha256")
    assert ver["result"]["valid"] is True


def test_rsa_wrong_message_fails():
    kg = compute_keygen(bits=512)
    n, e, d = kg["result"]["n"], kg["result"]["e"], kg["result"]["d"]

    sig = compute_sign(raw="68656c6c6f", encoding="hex", n_hex=n, d_hex=d)
    ver = compute_verify(raw="aabbccdd", encoding="hex", signature_raw=sig["result"]["signature"],
                         sig_encoding="hex", n_hex=n, e_hex=e)
    assert ver["result"]["valid"] is False
