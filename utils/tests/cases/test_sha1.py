"""SHA-1 测试。"""

from utils.hash.sha1 import compute


def test_sha1_abc():
    r = compute("616263", encoding="hex", output="hex")
    assert r["status_code"] == 0
    assert r["result"]["digest"] == "a9993e364706816aba3e25717850c26c9cd0d89d"


def test_sha1_empty():
    r = compute("", encoding="text", output="hex")
    assert r["status_code"] == 0
    assert r["result"]["digest"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
