"""自检引擎：运行测试向量并生成 PASS/FAIL 汇总。"""

from utils.tests.vectors import TEST_VECTORS
from utils.common.timing import measure_time


def _run_base64_case(case: dict) -> dict:
    from utils.encoding.base64_codec import encode, decode
    op = case["operation"]
    kwargs = {
        "output": case.get("output", "text"),
    }
    if op == "encode":
        kwargs["encoding"] = case.get("encoding", "text")
        result = encode(case["input"], **kwargs)
    else:
        kwargs["encoding"] = case.get("encoding", "text")
        result = decode(case["input"], **kwargs)

    actual = result["result"].get(case["expected_field"], "")
    expected = case["expected"]
    passed = actual == expected
    return {
        "name": case["name"],
        "pass": passed,
        "actual": actual,
        "expected": expected,
        "time_ms": result.get("time_ms", 0),
    }


def _run_utf8_case(case: dict) -> dict:
    from utils.encoding.utf8_codec import encode, decode
    op = case["operation"]
    kwargs = {"output": case.get("output", "hex")}
    if op == "encode":
        result = encode(case["input"], **kwargs)
    else:
        kwargs["encoding"] = case.get("encoding", "hex")
        result = decode(case["input"], **kwargs)

    actual = result["result"].get(case["expected_field"], "")
    expected = case["expected"]
    passed = actual == expected
    return {
        "name": case["name"],
        "pass": passed,
        "actual": actual,
        "expected": expected,
        "time_ms": result.get("time_ms", 0),
    }


def _run_sha256_case(case: dict) -> dict:
    from utils.hash.sha256 import compute
    result = compute(
        case["input"],
        encoding=case.get("encoding", "hex"),
        output=case.get("output", "hex"),
    )
    actual = result["result"].get(case["expected_field"], "")
    expected = case["expected"]
    passed = actual == expected
    return {
        "name": case["name"],
        "pass": passed,
        "actual": actual,
        "expected": expected,
        "time_ms": result.get("time_ms", 0),
    }


_DISPATCH = {
    "Base64": _run_base64_case,
    "UTF-8": _run_utf8_case,
    "SHA-256": _run_sha256_case,
}

# 占位算法（尚未实现）
_NOT_IMPLEMENTED = {"AES", "SM4", "RC6", "SHA-1", "SHA-3", "RIPEMD-160",
                    "HMAC", "PBKDF2", "RSA", "ECC", "ECDSA"}


def run_selftest(algorithms: list = None) -> dict:
    """运行自检。

    Args:
        algorithms: 要测试的算法列表，None 表示全部。

    Returns:
        dict: {"summary": {total, pass, fail}, "cases": [...]}
    """
    with measure_time() as mt:
        cases = []
        target_algos = algorithms or list(TEST_VECTORS.keys()) + list(_NOT_IMPLEMENTED)

        for algo in target_algos:
            if algo in _NOT_IMPLEMENTED:
                cases.append({
                    "name": algo,
                    "pass": None,
                    "actual": None,
                    "expected": None,
                    "time_ms": 0,
                    "status": "not_implemented",
                })
                continue

            runner = _DISPATCH.get(algo)
            vectors = TEST_VECTORS.get(algo, [])
            if not runner or not vectors:
                continue

            for case in vectors:
                try:
                    result = runner(case)
                except Exception as e:
                    result = {
                        "name": case["name"],
                        "pass": False,
                        "actual": str(e),
                        "expected": case["expected"],
                        "time_ms": 0,
                    }
                cases.append(result)

        total = len(cases)
        passed = sum(1 for c in cases if c["pass"] is True)
        failed = sum(1 for c in cases if c["pass"] is False)
        not_impl = sum(1 for c in cases if c.get("status") == "not_implemented")

    return {
        "status_code": 0,
        "status_message": "OK",
        "result": {
            "summary": {
                "total": total,
                "pass": passed,
                "fail": failed,
                "not_implemented": not_impl,
            },
            "cases": cases,
        },
        "time_ms": mt.time_ms,
    }
