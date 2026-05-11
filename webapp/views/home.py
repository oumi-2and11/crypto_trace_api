from flask import Blueprint, render_template

home_bp = Blueprint("home", __name__)


@home_bp.get("/")
def index():
    return render_template("index.html", page_title="首页")


@home_bp.get("/about")
def about():
    return render_template("about.html", page_title="关于")
