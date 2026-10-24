from pathlib import Path

from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect

from config import Config
from models import db
from auth import auth_bp, login_manager, register_admin_command
from documents import documents_bp
from pages import pages_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Create the upload directory if it does not exist.
    upload_folder = Path(app.config["UPLOAD_FOLDER"])
    upload_folder.mkdir(parents=True, exist_ok=True)

    # Initialize database.
    db.init_app(app)

    # Initialize authentication and CSRF protection.
    login_manager.init_app(app)
    CSRFProtect(app)

    # Register blueprints.
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(pages_bp)

    # Register Flask CLI commands.
    register_admin_command(app)

    # Prevent browsers and intermediate caches from storing pages.
    # This helps prevent protected pages from reappearing after logout.
    @app.after_request
    def add_no_cache_headers(response):
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, private, max-age=0"
        )
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    # Handle forbidden access.
    @app.errorhandler(403)
    def forbidden(error):
        return render_template("403.html"), 403

    # Handle uploads exceeding the configured size limit.
    @app.errorhandler(413)
    def too_large(error):
        return (
            "File too large. Maximum upload size is 16 MB.",
            413,
        )

    # Create missing tables without dropping existing tables.
    with app.app_context():
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
