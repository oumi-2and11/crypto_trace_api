from flask import Blueprint, redirect, render_template, url_for

encoding_bp = Blueprint("encoding", __name__, url_prefix="/encoding")


@encoding_bp.get("")
@encoding_bp.get("/")
def index():
    return redirect(url_for("encoding.base64"))


@encoding_bp.get("/base64")
def base64():
    return render_template("encoding/base64.html", page_title="Base64", current_algorithm="base64")


@encoding_bp.get("/utf8")
def utf8():
    return render_template("encoding/utf8.html", page_title="UTF-8", current_algorithm="utf8")
