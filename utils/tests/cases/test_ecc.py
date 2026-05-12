"""ECC 测试。"""

from utils.asymmetric.ecc import compute_keygen, _is_on_curve


def test_ecc_keygen_on_curve():
    kg = compute_keygen()
    px = int(kg["result"]["public_key_x"], 16)
    py = int(kg["result"]["public_key_y"], 16)
    assert _is_on_curve(px, py) is True


def test_ecc_keygen_trace():
    kg = compute_keygen(trace=True, trace_level=2)
    assert kg["trace"] is not None
    assert kg["trace"]["algorithm"] == "ECC"
