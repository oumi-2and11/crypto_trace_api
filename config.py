import os


class Config:
    DEBUG = os.getenv("FLASK_DEBUG", "true").lower() == "true"
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    TRACE_DEFAULT_ENABLED = os.getenv("TRACE_DEFAULT_ENABLED", "false").lower() == "true"
