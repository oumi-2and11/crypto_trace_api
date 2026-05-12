"""SHA-3 测试。"""

from utils.hash.sha3 import compute


def test_sha3_abc():
    r = compute("616263", encoding="hex", output="hex")
    assert r["status_code"] == 0
    assert r["result"]["digest"] == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"


def test_sha3_empty():
    r = compute("", encoding="text", output="hex")
    assert r["status_code"] == 0
    # SHA3-256("") 标准值
    assert r["result"]["digest"] == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
