
import re
from urllib.parse import urlsplit

import click

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_user,
    logout_user,
    login_required,
)
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from models import db, User, ActivityLog


# --------------------------------------------------
# Blueprint and Login Manager
# --------------------------------------------------

auth_bp = Blueprint("auth", __name__)

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"


# --------------------------------------------------
# User session loading
# --------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    """Load an existing active user into the session."""
    try:
        user = db.session.get(User, int(user_id))

        if user is None or not user.is_active:
            return None

        return user

    except (ValueError, TypeError):
        return None

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("User session loading failed")
        return None


@login_manager.unauthorized_handler
def handle_unauthorized():
    """Redirect unauthenticated requests to the login page."""
    flash("Please log in to continue.", "warning")
    return redirect(url_for("auth.login"))


# --------------------------------------------------
# Activity logging
# --------------------------------------------------

def record_activity(user_id, action, details=""):
    """
    Add an activity log to the current transaction.
    The calling function controls commit and rollback.
    """
    log = ActivityLog(
        user_id=user_id,
        action=str(action)[:100],
        details=str(details or "")[:500],
    )
    db.session.add(log)


# --------------------------------------------------
# Input validation
# --------------------------------------------------

def valid_username(username):
    """Allow letters, digits, underscores, periods and hyphens."""
    if not isinstance(username, str):
        return False

    return bool(
        3 <= len(username) <= 80
        and re.fullmatch(r"[A-Za-z0-9_.-]+", username)
    )


def valid_email(email):
    """Perform basic email format validation."""
    if not isinstance(email, str):
        return False

    if not email or len(email) > 120:
        return False

    if any(character.isspace() for character in email):
        return False

    if email.count("@") != 1:
        return False

    local_part, domain = email.rsplit("@", 1)

    if not local_part or len(local_part) > 64:
        return False

    if not domain or len(domain) > 253:
        return False

    if "." not in domain:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    domain_labels = domain.split(".")

    for label in domain_labels:
        if not label or len(label) > 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            return False

    return True


def valid_password(password, minimum_length=8):
    """Validate password length without changing the password."""
    return (
        isinstance(password, str)
        and minimum_length <= len(password) <= 256
    )


def render_auth_template(template_name):
    return render_template(template_name)


def is_safe_next_url(target):
    """
    Permit only local absolute-path redirects.
    Reject external URLs, protocol-relative URLs and backslashes.
    """
    if not isinstance(target, str) or not target:
        return False

    if not target.startswith("/") or target.startswith("//"):
        return False

    if "\\" in target:
        return False

    if any(ord(character) < 32 for character in target):
        return False

    try:
        parsed = urlsplit(target)
    except ValueError:
        return False

    return not parsed.scheme and not parsed.netloc


# --------------------------------------------------
# Registration
# --------------------------------------------------

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("pages.dashboard"))

    if request.method == "GET":
        return render_auth_template("register.html")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not username or not email or not password or not confirm_password:
        flash("Please fill in all required fields.", "error")
        return render_auth_template("register.html")

    if not valid_username(username):
        flash(
            "Username must be 3–80 characters and contain only "
            "letters, numbers, underscores, periods or hyphens.",
            "error",
        )
        return render_auth_template("register.html")

    if not valid_email(email):
        flash("Please enter a valid email address.", "error")
        return render_auth_template("register.html")

    if not valid_password(password, minimum_length=8):
        flash(
            "Password must be between 8 and 256 characters.",
            "error",
        )
        return render_auth_template("register.html")

    if password != confirm_password:
        flash("Passwords do not match.", "error")
        return render_auth_template("register.html")

    try:
        existing_user = db.session.execute(
            select(User.id).where(
                or_(
                    User.username == username,
                    User.email == email,
                )
            ).limit(1)
        ).first()

        if existing_user:
            flash("Username or email already exists.", "error")
            return render_auth_template("register.html")

        # Public registration must never grant administrator privileges.
        # Keep the existing owner role for compatibility with this project.
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role="owner",
            is_active=True,
        )

        db.session.add(user)
        db.session.flush()

        record_activity(
            user.id,
            "REGISTER",
            "Owner account registered",
        )

        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("auth.login"))

    except IntegrityError:
        db.session.rollback()
        flash(
            "Username or email already exists. Please try another.",
            "error",
        )

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("Registration database error")
        flash(
            "Registration could not be completed. Please try again.",
            "error",
        )

    return render_auth_template("register.html")


# --------------------------------------------------
# Login
# --------------------------------------------------

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("pages.dashboard"))

    if request.method == "GET":
        return render_auth_template("login.html")

    identifier = request.form.get("identifier", "").strip()
    password = request.form.get("password", "")

    if not identifier or not password:
        flash(
            "Please enter your username/email and password.",
            "error",
        )
        return render_auth_template("login.html")

    if len(identifier) > 120 or len(password) > 256:
        flash("Invalid credentials.", "error")
        return render_auth_template("login.html")

    try:
        user = db.session.execute(
            select(User).where(
                or_(
                    User.username == identifier,
                    User.email == identifier.lower(),
                )
            ).limit(1)
        ).scalar_one_or_none()

        if (
            user is None
            or not user.is_active
            or not check_password_hash(
                user.password_hash,
                password,
            )
        ):
            flash("Invalid credentials or inactive account.", "error")
            return render_auth_template("login.html")

        record_activity(
            user.id,
            "LOGIN",
            "Successful login",
        )
        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("Login database error")
        flash(
            "Login could not be completed. Please try again.",
            "error",
        )
        return render_auth_template("login.html")

    # Establish the authenticated session only after successful
    # credential verification and audit-log commit.
    login_user(user, remember=False)

    next_page = request.args.get("next", "")

    if is_safe_next_url(next_page):
        return redirect(next_page)

    return redirect(url_for("pages.dashboard"))


# --------------------------------------------------
# Logout
# --------------------------------------------------

@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    user_id = current_user.id

    try:
        record_activity(
            user_id,
            "LOGOUT",
            "User logged out",
        )
        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("Logout audit log error")

    # Always terminate the session, even if audit logging fails.
    logout_user()

    flash("You have logged out.", "success")
    return redirect(url_for("auth.login"))


# --------------------------------------------------
# Admin creation CLI command
# --------------------------------------------------

def register_admin_command(app):
    """Register the create-admin Flask CLI command."""

    @app.cli.command("create-admin")
    @click.option(
        "--username",
        prompt=True,
        help="Administrator username.",
    )
    @click.option(
        "--email",
        prompt=True,
        help="Administrator email address.",
    )
    @click.password_option(
        confirmation_prompt=True,
        help="Administrator password.",
    )
    def create_admin(username, email, password):
        """Create an administrator account from the terminal."""

        username = username.strip()
        email = email.strip().lower()

        if not valid_username(username):
            raise click.ClickException(
                "Username must be 3–80 characters and contain only "
                "letters, numbers, underscores, periods or hyphens."
            )

        if not valid_email(email):
            raise click.ClickException(
                "Please provide a valid email address."
            )

        if not valid_password(password, minimum_length=12):
            raise click.ClickException(
                "Admin password must be between 12 and 256 characters."
            )

        try:
            existing_user = db.session.execute(
                select(User.id).where(
                    or_(
                        User.username == username,
                        User.email == email,
                    )
                ).limit(1)
            ).first()

            if existing_user:
                raise click.ClickException(
                    "Username or email already exists."
                )

            admin = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role="admin",
                is_active=True,
            )

            db.session.add(admin)
            db.session.flush()

            record_activity(
                admin.id,
                "ADMIN_CREATED",
                "Administrator account created through CLI",
            )

            db.session.commit()

            click.echo("Administrator account created successfully.")

        except click.ClickException:
            db.session.rollback()
            raise

        except IntegrityError as exc:
            db.session.rollback()
            raise click.ClickException(
                "Username or email already exists."
            ) from exc

        except SQLAlchemyError as exc:
            db.session.rollback()
            current_app.logger.exception(
                "Admin creation database error"
            )
            raise click.ClickException(
                "Could not create administrator. Check application logs."
            ) from exc
