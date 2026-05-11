from flask import Blueprint, redirect, render_template, url_for

asymmetric_bp = Blueprint("asymmetric", __name__, url_prefix="/asymmetric")


@asymmetric_bp.get("")
@asymmetric_bp.get("/")
def index():
    return redirect(url_for("asymmetric.rsa"))


@asymmetric_bp.get("/rsa")
def rsa():
    return render_template("asymmetric/rsa.html", page_title="RSA", current_algorithm="rsa")


@asymmetric_bp.get("/rsa_sha1")
def rsa_sha1():
    return render_template("asymmetric/rsa_sha1.html", page_title="RSA-SHA1", current_algorithm="rsa_sha1")


@asymmetric_bp.get("/ecc")
def ecc():
    return render_template("asymmetric/ecc.html", page_title="ECC", current_algorithm="ecc")


@asymmetric_bp.get("/ecdsa")
def ecdsa():
    return render_template("asymmetric/ecdsa.html", page_title="ECDSA", current_algorithm="ecdsa")
