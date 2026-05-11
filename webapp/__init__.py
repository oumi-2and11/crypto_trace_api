from flask import Flask, render_template, jsonify

from .views.asymmetric_views import asymmetric_bp
from .views.encoding_views import encoding_bp
from .views.hash_views import hash_bp
from .views.home import home_bp
from .views.selftest_views import selftest_bp
from .views.symmetric_views import symmetric_bp

# API 蓝图
from .views.encoding_api import encoding_api_bp
from .views.hash_api import hash_api_bp
from .views.selftest_api import selftest_api_bp
from .views.symmetric_api import symmetric_api_bp
from .views.hmac_kdf_api import hmac_kdf_api_bp


TOP_NAV = [
    {"name": "首页", "endpoint": "home.index"},
    {"name": "对称加密", "endpoint": "symmetric.index"},
    {"name": "哈希与派生", "endpoint": "hash.index"},
    {"name": "编码", "endpoint": "encoding.index"},
    {"name": "公钥与签名", "endpoint": "asymmetric.index"},
    {"name": "SelfTest", "endpoint": "selftest.index"},
    {"name": "关于", "endpoint": "home.about"},
]


def create_app(config_object: str = "config.Config") -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(config_object)

    app.register_blueprint(home_bp)
    app.register_blueprint(symmetric_bp)
    app.register_blueprint(hash_bp)
    app.register_blueprint(encoding_bp)
    app.register_blueprint(asymmetric_bp)
    app.register_blueprint(selftest_bp)

    # API 蓝图
    app.register_blueprint(encoding_api_bp)
    app.register_blueprint(hash_api_bp)
    app.register_blueprint(selftest_api_bp)
    app.register_blueprint(symmetric_api_bp)
    app.register_blueprint(hmac_kdf_api_bp)

    @app.context_processor
    def inject_nav_data():
        return {"top_nav": TOP_NAV}

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="页面不存在"), 404

    @app.errorhandler(500)
    def server_error(_error):
        return render_template("error.html", code=500, message="服务器内部错误"), 500

    return app
