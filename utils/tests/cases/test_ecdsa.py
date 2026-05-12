"""ECDSA 测试。"""

from utils.asymmetric.ecc import compute_keygen
from utils.asymmetric.ecdsa import compute_sign, compute_verify


def test_ecdsa_sign_verify():
    kg = compute_keygen()
    priv = kg["result"]["private_key"]
    px = kg["result"]["public_key_x"]
    py = kg["result"]["public_key_y"]

    sig = compute_sign(raw="68656c6c6f", encoding="hex", private_key_hex=priv, hash_algo="sha256")
    assert sig["status_code"] == 0
    assert len(sig["result"]["r"]) > 0
    assert len(sig["result"]["s"]) > 0

    ver = compute_verify(raw="68656c6c6f", encoding="hex", r_hex=sig["result"]["r"],
                         s_hex=sig["result"]["s"], pub_x_hex=px, pub_y_hex=py, hash_algo="sha256")
    assert ver["result"]["valid"] is True


def test_ecdsa_wrong_message_fails():
    kg = compute_keygen()
    priv = kg["result"]["private_key"]
    px = kg["result"]["public_key_x"]
    py = kg["result"]["public_key_y"]

    sig = compute_sign(raw="68656c6c6f", encoding="hex", private_key_hex=priv)
    ver = compute_verify(raw="aabbccdd", encoding="hex", r_hex=sig["result"]["r"],
                         s_hex=sig["result"]["s"], pub_x_hex=px, pub_y_hex=py)
    assert ver["result"]["valid"] is False
