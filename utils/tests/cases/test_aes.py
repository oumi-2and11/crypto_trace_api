"""AES-128 测试。"""

from utils.symmetric.aes import compute_encrypt, compute_decrypt


def test_aes_encrypt_fips197():
    r = compute_encrypt(
        raw="6bc1bee22e409f96e93d7e117393172a",
        key_raw="2b7e151628aed2a6abf7158809cf4f3c",
        mode="ECB", padding="none", output="hex",
    )
    assert r["status_code"] == 0
    assert r["result"]["ciphertext"] == "3ad77bb40d7a3660a89ecaf32466ef97"


def test_aes_decrypt_fips197():
    r = compute_decrypt(
        raw="3ad77bb40d7a3660a89ecaf32466ef97",
        key_raw="2b7e151628aed2a6abf7158809cf4f3c",
        mode="ECB", padding="none", output="hex",
    )
    assert r["status_code"] == 0
    assert r["result"]["plaintext"] == "6bc1bee22e409f96e93d7e117393172a"


def test_aes_ecb_roundtrip():
    data = "00112233445566778899aabbccddeeff"
    key = "000102030405060708090a0b0c0d0e0f"
    enc = compute_encrypt(raw=data, key_raw=key, mode="ECB", padding="none")
    dec = compute_decrypt(raw=enc["result"]["ciphertext"], key_raw=key, mode="ECB", padding="none")
    assert dec["result"]["plaintext"] == data
