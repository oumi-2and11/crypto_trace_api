"""SM4 测试。"""

from utils.symmetric.sm4 import compute_encrypt, compute_decrypt


def test_sm4_encrypt_gbt32907():
    r = compute_encrypt(
        raw="0123456789abcdeffedcba9876543210",
        key_raw="0123456789abcdeffedcba9876543210",
        mode="ECB", padding="none", output="hex",
    )
    assert r["status_code"] == 0
    assert r["result"]["ciphertext"] == "681edf34d206965e86b3e94f536e4246"


def test_sm4_decrypt_gbt32907():
    r = compute_decrypt(
        raw="681edf34d206965e86b3e94f536e4246",
        key_raw="0123456789abcdeffedcba9876543210",
        mode="ECB", padding="none", output="hex",
    )
    assert r["status_code"] == 0
    assert r["result"]["plaintext"] == "0123456789abcdeffedcba9876543210"


def test_sm4_ecb_roundtrip():
    key = "0123456789abcdeffedcba9876543210"
    data = "00112233445566778899aabbccddeeff"
    enc = compute_encrypt(raw=data, key_raw=key, mode="ECB", padding="none")
    dec = compute_decrypt(raw=enc["result"]["ciphertext"], key_raw=key, mode="ECB", padding="none")
    assert dec["result"]["plaintext"] == data
