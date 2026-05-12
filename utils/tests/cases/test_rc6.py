"""RC6 测试。"""

from utils.symmetric.rc6 import compute_encrypt, compute_decrypt


def test_rc6_encrypt_allzero():
    r = compute_encrypt(
        raw="00000000000000000000000000000000",
        key_raw="00000000000000000000000000000000",
        mode="ECB", padding="none", output="hex",
    )
    assert r["status_code"] == 0
    assert r["result"]["ciphertext"] == "8fc3a53656b1f778c129df4e9848a41e"


def test_rc6_decrypt_allzero():
    r = compute_decrypt(
        raw="8fc3a53656b1f778c129df4e9848a41e",
        key_raw="00000000000000000000000000000000",
        mode="ECB", padding="none", output="hex",
    )
    assert r["status_code"] == 0
    assert r["result"]["plaintext"] == "00000000000000000000000000000000"


def test_rc6_roundtrip():
    key = "0102030405060708090a0b0c0d0e0f10"
    enc = compute_encrypt(raw="00000000000000000000000000000000", key_raw=key, mode="ECB", padding="none")
    dec = compute_decrypt(raw=enc["result"]["ciphertext"], key_raw=key, mode="ECB", padding="none")
    assert dec["result"]["plaintext"] == "00000000000000000000000000000000"
