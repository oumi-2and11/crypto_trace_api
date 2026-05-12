"""UTF-8 编解码测试。"""

from utils.encoding.utf8_codec import encode, decode


def test_utf8_encode_ascii():
    r = encode("ABC", output="hex")
    assert r["status_code"] == 0
    assert r["result"]["data"] == "414243"


def test_utf8_encode_chinese():
    r = encode("中文", output="hex")
    assert r["status_code"] == 0
    assert r["result"]["data"] == "e4b8ade69687"


def test_utf8_decode_hex():
    r = decode("e4b8ade69687", encoding="hex", output="text")
    assert r["status_code"] == 0
    assert r["result"]["data"] == "中文"


def test_utf8_roundtrip():
    original = "Hello 世界!"
    enc = encode(original, output="hex")
    dec = decode(enc["result"]["data"], encoding="hex", output="text")
    assert dec["result"]["data"] == original
