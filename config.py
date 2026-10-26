
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DB_CONFIG = {
    "host": os.environ.get("LMS_DB_HOST", "localhost"),
    "user": os.environ.get("LMS_DB_USER", "root"),
    "password": os.environ.get("LMS_DB_PASSWORD", "1234"),
    "database": os.environ.get(
        "LMS_DB_NAME",
        "learning_management_db"
    ),
}

SECRET_KEY = os.environ.get("LMS_SECRET_KEY")

if not SECRET_KEY:
    # Local development only. Set LMS_SECRET_KEY before deployment.
    SECRET_KEY = "dev-only-change-this-key-before-deployment"

UPLOAD_FOLDER = str(BASE_DIR / "static" / "videos")

MAX_CONTENT_LENGTH = 500 * 1024 * 1024

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

# Enable only when the site is served over HTTPS.
SESSION_COOKIE_SECURE = (
    os.environ.get("LMS_HTTPS", "0") == "1"
)
