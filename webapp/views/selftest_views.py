from flask import Blueprint, render_template

selftest_bp = Blueprint("selftest", __name__)


@selftest_bp.get("/selftest")
def index():
    return render_template("selftest.html", page_title="SelfTest")
