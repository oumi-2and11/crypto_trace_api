"""SHA-256 测试。"""

from utils.hash.sha256 import compute


def test_sha256_abc():
    r = compute("616263", encoding="hex", output="hex")
    assert r["status_code"] == 0
    assert r["result"]["digest"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_empty():
    r = compute("", encoding="text", output="hex")
    assert r["status_code"] == 0
    assert r["result"]["digest"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_trace():
    r = compute("616263", encoding="hex", output="hex", trace=True, trace_level=2)
    assert r["trace"] is not None
    assert r["trace"]["algorithm"] == "SHA-256"
