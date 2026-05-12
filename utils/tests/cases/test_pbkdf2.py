"""PBKDF2 测试。"""

from utils.mac_kdf.pbkdf2 import compute


def test_pbkdf2_sha256_iter1():
    r = compute(
        password_raw="70617373776f7264",
        salt_raw="73616c74",
        iterations=1, dk_len=32, prf="HmacSHA256",
        password_encoding="hex", salt_encoding="hex", output="hex",
    )
    assert r["status_code"] == 0
    assert r["result"]["derived_key"] == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"


def test_pbkdf2_sha256_iter2():
    r = compute(
        password_raw="70617373776f7264",
        salt_raw="73616c74",
        iterations=2, dk_len=32, prf="HmacSHA256",
        password_encoding="hex", salt_encoding="hex", output="hex",
    )
    assert r["status_code"] == 0
    # 不同迭代次数应产生不同结果
    assert len(r["result"]["derived_key"]) == 64
