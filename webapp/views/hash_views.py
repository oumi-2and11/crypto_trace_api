from flask import Blueprint, redirect, render_template, url_for

hash_bp = Blueprint("hash", __name__, url_prefix="/hash")


@hash_bp.get("")
@hash_bp.get("/")
def index():
    return redirect(url_for("hash.sha256"))


@hash_bp.get("/sha1")
def sha1():
    return render_template("hash/sha1.html", page_title="SHA1", current_algorithm="sha1")


@hash_bp.get("/sha256")
def sha256():
    return render_template("hash/sha256.html", page_title="SHA256", current_algorithm="sha256")


@hash_bp.get("/sha3")
def sha3():
    return render_template("hash/sha3.html", page_title="SHA3", current_algorithm="sha3")


@hash_bp.get("/ripemd160")
def ripemd160():
    return render_template("hash/ripemd160.html", page_title="RIPEMD160", current_algorithm="ripemd160")


@hash_bp.get("/hmac_sha1")
def hmac_sha1():
    return render_template("hash/hmac_sha1.html", page_title="HMAC-SHA1", current_algorithm="hmac_sha1")


@hash_bp.get("/hmac_sha256")
def hmac_sha256():
    return render_template("hash/hmac_sha256.html", page_title="HMAC-SHA256", current_algorithm="hmac_sha256")


@hash_bp.get("/pbkdf2")
def pbkdf2():
    return render_template("hash/pbkdf2.html", page_title="PBKDF2", current_algorithm="pbkdf2")
