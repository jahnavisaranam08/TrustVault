
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from the project's .env file.
load_dotenv(BASE_DIR / ".env")


class Config:
    # Application security.
    SECRET_KEY = os.environ.get("SECRET_KEY")

    if not SECRET_KEY or not SECRET_KEY.strip():
        raise RuntimeError(
            "SECRET_KEY is missing. Add a strong random key to your .env file."
        )

    # Existing SQLite database. Do not delete or recreate this file.
    SQLALCHEMY_DATABASE_URI = (
        "sqlite:///" + str(BASE_DIR / "trustvault.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File uploads.
    UPLOAD_FOLDER = str(BASE_DIR / "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

    ALLOWED_EXTENSIONS = {
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "txt",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "csv",
    }

    # Session cookie security.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Local HTTP development: false.
    # Production with HTTPS: set COOKIE_SECURE=true in .env.
    SESSION_COOKIE_SECURE = (
        os.environ.get("COOKIE_SECURE", "false").strip().lower() == "true"
    )
