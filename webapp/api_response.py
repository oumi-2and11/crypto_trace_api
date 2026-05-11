"""API 统一响应封装与蓝图注册。"""

from flask import Blueprint, jsonify, request
from utils.common.validation import CryptoError, STATUS_CODES


def make_response(status_code=0, status_message=None, result=None,
                 trace=None, time_ms=None):
    resp = {
        "status_code": status_code,
        "status_message": status_message or STATUS_CODES.get(status_code, "Unknown"),
    }
    if result is not None:
        resp["result"] = result
    else:
        resp["result"] = None
    resp["trace"] = trace
    resp["time_ms"] = round(time_ms, 3) if time_ms is not None else None
    return resp


def handle_api_call(func):
    """装饰器：统一处理 JSON 解析、CryptoError、异常。"""
    def wrapper(*args, **kwargs):
        import time as _time
        start = _time.perf_counter()
        try:
            data = request.get_json(silent=True)
            if data is None:
                data = {}
            result = func(data, *args, **kwargs)
            if isinstance(result, dict) and "status_code" in result:
                result["time_ms"] = result.get("time_ms") or round((_time.perf_counter() - start) * 1000, 3)
                return jsonify(result)
            return jsonify(result)
        except CryptoError as e:
            return jsonify(make_response(
                e.status_code, e.status_message, time_ms=(_time.perf_counter() - start) * 1000
            ))
        except Exception as e:
            return jsonify(make_response(
                9001, str(e), time_ms=(_time.perf_counter() - start) * 1000
            ))
    wrapper.__name__ = func.__name__
    wrapper.__qualname__ = func.__qualname__
    return wrapper


def create_api_blueprint(name: str, import_name: str, url_prefix: str) -> Blueprint:
    return Blueprint(name, import_name, url_prefix=url_prefix)
