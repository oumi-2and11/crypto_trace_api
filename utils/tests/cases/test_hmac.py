"""HMAC 测试。"""

from utils.mac_kdf.hmac import compute


def test_hmac_sha256_rfc4231():
    r = compute(
        key_raw="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data_raw="4869205468657265",
        algorithm="HmacSHA256",
        key_encoding="hex", data_encoding="hex", output="hex",
    )
    assert r["status_code"] == 0
    assert r["result"]["mac"] == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"


def test_hmac_sha1():
    r = compute(
        key_raw="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data_raw="4869205468657265",
        algorithm="HmacSHA1",
        key_encoding="hex", data_encoding="hex", output="hex",
    )
    assert r["status_code"] == 0
    assert len(r["result"]["mac"]) == 40  # SHA-1 = 20 bytes = 40 hex
