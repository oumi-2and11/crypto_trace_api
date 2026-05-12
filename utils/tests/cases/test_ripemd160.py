"""RIPEMD-160 测试。"""

from utils.hash.ripemd160 import compute


def test_ripemd160_abc():
    r = compute("616263", encoding="hex", output="hex")
    assert r["status_code"] == 0
    assert r["result"]["digest"] == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"


def test_ripemd160_empty():
    r = compute("", encoding="text", output="hex")
    assert r["status_code"] == 0
    assert r["result"]["digest"] == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
