"""Base64 编解码测试。"""

from utils.encoding.base64_codec import encode, decode


def test_base64_encode_text():
    r = encode("hello", encoding="text", output="text")
    assert r["status_code"] == 0
    assert r["result"]["base64"] == "aGVsbG8="


def test_base64_encode_chinese():
    r = encode("中文", encoding="text", output="text")
    assert r["status_code"] == 0
    assert r["result"]["base64"] == "5Lit5paH"


def test_base64_decode():
    r = decode("aGVsbG8=", encoding="text", output="text")
    assert r["status_code"] == 0
    assert r["result"]["data"] == "hello"


def test_base64_roundtrip():
    original = "CryptoTrace 测试数据 123!@#"
    enc = encode(original, encoding="text", output="text")
    dec = decode(enc["result"]["base64"], encoding="text", output="text")
    assert dec["result"]["data"] == original
