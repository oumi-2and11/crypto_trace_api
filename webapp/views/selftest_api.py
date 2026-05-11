"""自检 API 端点。"""

from flask import Blueprint
from webapp.api_response import handle_api_call

selftest_api_bp = Blueprint("selftest_api", __name__, url_prefix="/api/selftest")


@selftest_api_bp.route("/run", methods=["POST"])
@handle_api_call
def selftest_run(data):
    from utils.tests.selftest import run_selftest

    algorithms = data.get("algorithms", None)
    return run_selftest(algorithms)
