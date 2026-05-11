"""自检引擎：运行测试向量并生成 PASS/FAIL 汇总。"""

from utils.tests.vectors import TEST_VECTORS
from utils.common.timing import measure_time


def _generic_hash_runner(algo_module: str, algo_func: str):
    """生成通用哈希测试 runner。"""
    def runner(case: dict) -> dict:
        import importlib
        mod = importlib.import_module(algo_module)
        func = getattr(mod, algo_func)
        result = func(
            case["input"],
            encoding=case.get("encoding", "hex"),
            output=case.get("output", "hex"),
        )
        actual = result["result"].get(case["expected_field"], "")
        expected = case["expected"]
        return {
            "name": case["name"],
            "pass": actual == expected,
            "actual": actual,
            "expected": expected,
            "time_ms": result.get("time_ms", 0),
        }
    return runner


def _run_base64_case(case: dict) -> dict:
    from utils.encoding.base64_codec import encode, decode
    op = case["operation"]
    kwargs = {"output": case.get("output", "text")}
    if op == "encode":
        kwargs["encoding"] = case.get("encoding", "text")
        result = encode(case["input"], **kwargs)
    else:
        kwargs["encoding"] = case.get("encoding", "text")
        result = decode(case["input"], **kwargs)

    actual = result["result"].get(case["expected_field"], "")
    return {
        "name": case["name"],
        "pass": actual == case["expected"],
        "actual": actual,
        "expected": case["expected"],
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
    return {
        "name": case["name"],
        "pass": actual == case["expected"],
        "actual": actual,
        "expected": case["expected"],
        "time_ms": result.get("time_ms", 0),
    }


def _run_aes_case(case: dict) -> dict:
    from utils.symmetric.aes import compute_encrypt, compute_decrypt
    op = case["operation"]
    kwargs = {
        "key_raw": case["key"],
        "encoding": "hex", "key_encoding": "hex",
        "mode": case.get("mode", "ECB"),
        "padding": case.get("padding", "pkcs7"),
        "output": case.get("output", "hex"),
    }
    if op == "encrypt":
        result = compute_encrypt(case["input"], **kwargs)
    else:
        result = compute_decrypt(case["input"], **kwargs)

    actual = result["result"].get(case["expected_field"], "")
    return {
        "name": case["name"],
        "pass": actual == case["expected"],
        "actual": actual,
        "expected": case["expected"],
        "time_ms": result.get("time_ms", 0),
    }


def _run_hmac_case(case: dict) -> dict:
    from utils.mac_kdf.hmac import compute
    result = compute(
        key_raw=case["key"], data_raw=case["data"],
        algorithm=case.get("algorithm", "HmacSHA256"),
        key_encoding="hex", data_encoding="hex",
        output=case.get("output", "hex"),
    )
    actual = result["result"].get(case["expected_field"], "")
    return {
        "name": case["name"],
        "pass": actual == case["expected"],
        "actual": actual,
        "expected": case["expected"],
        "time_ms": result.get("time_ms", 0),
    }


def _run_pbkdf2_case(case: dict) -> dict:
    from utils.mac_kdf.pbkdf2 import compute
    result = compute(
        password_raw=case["password"], salt_raw=case["salt"],
        iterations=case.get("iterations", 1),
        dk_len=case.get("dk_len", 32),
        prf=case.get("prf", "HmacSHA256"),
        password_encoding="hex", salt_encoding="hex",
        output=case.get("output", "hex"),
    )
    actual = result["result"].get(case["expected_field"], "")
    return {
        "name": case["name"],
        "pass": actual == case["expected"],
        "actual": actual,
        "expected": case["expected"],
        "time_ms": result.get("time_ms", 0),
    }


def _run_rsa_case(case: dict) -> dict:
    from utils.asymmetric.rsa import compute_keygen, compute_sign, compute_verify
    bits = case.get("bits", 1024)
    data_raw = case.get("data", "")
    encoding = case.get("encoding", "hex")
    hash_algo = case.get("hash_algo", "sha256")

    try:
        kg = compute_keygen(bits=bits)
        n_hex = kg["result"]["n"]
        e_hex = kg["result"]["e"]
        d_hex = kg["result"]["d"]

        sig = compute_sign(raw=data_raw, encoding=encoding,
                           n_hex=n_hex, d_hex=d_hex, hash_algo=hash_algo)
        sig_str = sig["result"]["signature"]

        ver = compute_verify(raw=data_raw, encoding=encoding,
                             signature_raw=sig_str, sig_encoding="hex",
                             n_hex=n_hex, e_hex=e_hex, hash_algo=hash_algo)
        actual = ver["result"]["valid"]
    except Exception as e:
        return {
            "name": case["name"],
            "pass": False,
            "actual": str(e),
            "expected": case["expected"],
            "time_ms": 0,
        }

    expected = case["expected"]
    return {
        "name": case["name"],
        "pass": actual == expected,
        "actual": actual,
        "expected": expected,
        "time_ms": kg.get("time_ms", 0) + sig.get("time_ms", 0) + ver.get("time_ms", 0),
    }


def _run_rsa_sha1_case(case: dict) -> dict:
    from utils.asymmetric.rsa import compute_keygen
    from utils.asymmetric.rsa_sha1 import compute_sign, compute_verify
    bits = case.get("bits", 1024)
    data_raw = case.get("data", "")
    encoding = case.get("encoding", "hex")

    try:
        kg = compute_keygen(bits=bits)
        n_hex = kg["result"]["n"]
        e_hex = kg["result"]["e"]
        d_hex = kg["result"]["d"]

        sig = compute_sign(raw=data_raw, encoding=encoding,
                           n_hex=n_hex, d_hex=d_hex)
        sig_str = sig["result"]["signature"]

        ver = compute_verify(raw=data_raw, encoding=encoding,
                             signature_raw=sig_str, sig_encoding="hex",
                             n_hex=n_hex, e_hex=e_hex)
        actual = ver["result"]["valid"]
    except Exception as e:
        return {
            "name": case["name"],
            "pass": False,
            "actual": str(e),
            "expected": case["expected"],
            "time_ms": 0,
        }

    expected = case["expected"]
    return {
        "name": case["name"],
        "pass": actual == expected,
        "actual": actual,
        "expected": expected,
        "time_ms": kg.get("time_ms", 0) + sig.get("time_ms", 0) + ver.get("time_ms", 0),
    }


def _run_ecc_case(case: dict) -> dict:
    from utils.asymmetric.ecc import compute_keygen, _is_on_curve

    try:
        kg = compute_keygen()
        px = int(kg["result"]["public_key_x"], 16)
        py = int(kg["result"]["public_key_y"], 16)
        actual = _is_on_curve(px, py)
    except Exception as e:
        return {
            "name": case["name"],
            "pass": False,
            "actual": str(e),
            "expected": case["expected"],
            "time_ms": 0,
        }

    expected = case["expected"]
    return {
        "name": case["name"],
        "pass": actual == expected,
        "actual": actual,
        "expected": expected,
        "time_ms": kg.get("time_ms", 0),
    }


def _run_ecdsa_case(case: dict) -> dict:
    from utils.asymmetric.ecc import compute_keygen
    from utils.asymmetric.ecdsa import compute_sign, compute_verify
    data_raw = case.get("data", "")
    encoding = case.get("encoding", "hex")
    hash_algo = case.get("hash_algo", "sha256")

    try:
        kg = compute_keygen()
        priv_hex = kg["result"]["private_key"]
        pub_x_hex = kg["result"]["public_key_x"]
        pub_y_hex = kg["result"]["public_key_y"]

        sig = compute_sign(raw=data_raw, encoding=encoding,
                           private_key_hex=priv_hex, hash_algo=hash_algo)
        r_hex = sig["result"]["r"]
        s_hex = sig["result"]["s"]

        ver = compute_verify(raw=data_raw, encoding=encoding,
                             r_hex=r_hex, s_hex=s_hex,
                             pub_x_hex=pub_x_hex, pub_y_hex=pub_y_hex,
                             hash_algo=hash_algo)
        actual = ver["result"]["valid"]
    except Exception as e:
        return {
            "name": case["name"],
            "pass": False,
            "actual": str(e),
            "expected": case["expected"],
            "time_ms": 0,
        }

    expected = case["expected"]
    return {
        "name": case["name"],
        "pass": actual == expected,
        "actual": actual,
        "expected": expected,
        "time_ms": kg.get("time_ms", 0) + sig.get("time_ms", 0) + ver.get("time_ms", 0),
    }


_DISPATCH = {
    "Base64": _run_base64_case,
    "UTF-8": _run_utf8_case,
    "SHA-256": _generic_hash_runner("utils.hash.sha256", "compute"),
    "SHA-1": _generic_hash_runner("utils.hash.sha1", "compute"),
    "SHA-3": _generic_hash_runner("utils.hash.sha3", "compute"),
    "RIPEMD-160": _generic_hash_runner("utils.hash.ripemd160", "compute"),
    "AES": _run_aes_case,
    "HMAC": _run_hmac_case,
    "PBKDF2": _run_pbkdf2_case,
    "RSA": _run_rsa_case,
    "RSA-SHA1": _run_rsa_sha1_case,
    "ECC": _run_ecc_case,
    "ECDSA": _run_ecdsa_case,
}

_NOT_IMPLEMENTED = {"SM4", "RC6"}


def run_selftest(algorithms: list = None) -> dict:
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
