from flask import Blueprint, redirect, render_template, url_for

symmetric_bp = Blueprint("symmetric", __name__, url_prefix="/symmetric")


@symmetric_bp.get("")
@symmetric_bp.get("/")
def index():
    return redirect(url_for("symmetric.aes"))


@symmetric_bp.get("/aes")
def aes():
    return render_template("symmetric/aes.html", page_title="AES", current_algorithm="aes")


@symmetric_bp.get("/sm4")
def sm4():
    return render_template("symmetric/sm4.html", page_title="SM4", current_algorithm="sm4")


@symmetric_bp.get("/rc6")
def rc6():
    return render_template("symmetric/rc6.html", page_title="RC6", current_algorithm="rc6")
