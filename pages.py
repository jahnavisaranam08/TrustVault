
from functools import wraps

from flask import (
    Blueprint,
    render_template,
    request,
    abort,
    redirect,
    url_for,
    flash,
)
from flask_login import login_required, current_user
from sqlalchemy import or_, func
from sqlalchemy.exc import SQLAlchemyError

from models import db, User, Document, DocumentShare, ActivityLog
from security import roles_required


pages_bp = Blueprint("pages", __name__)


# ---------------------------------------------------------
# Authentication helper
# ---------------------------------------------------------

def active_login_required(view_function):
    """Require login and reject inactive accounts."""

    @wraps(view_function)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_active:
            abort(403)

        return view_function(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------
# Shared document visibility query
# ---------------------------------------------------------

def visible_documents_query():
    """
    Admins can see all documents.
    Other users can see their own documents and documents
    explicitly shared with them.
    """

    query = Document.query

    if current_user.role != "admin":
        shared_ids = db.session.query(
            DocumentShare.document_id
        ).filter(
            DocumentShare.user_id == current_user.id
        )

        query = query.filter(
            or_(
                Document.owner_id == current_user.id,
                Document.id.in_(shared_ids),
            )
        )

    return query


# ---------------------------------------------------------
# Shared With Me query
# ---------------------------------------------------------

def shared_with_me_query():
    """
    Return documents owned by other active users and shared
    with the current user using read or edit permission.
    """

    return Document.query.join(
        DocumentShare,
        DocumentShare.document_id == Document.id,
    ).join(
        User,
        User.id == Document.owner_id,
    ).filter(
        DocumentShare.user_id == current_user.id,
        Document.owner_id != current_user.id,
        User.is_active.is_(True),
        DocumentShare.permission.in_(("read", "edit")),
    ).distinct()


# ---------------------------------------------------------
# Dashboard
# ---------------------------------------------------------

@pages_bp.route("/")
@active_login_required
def dashboard():

    shared_count = shared_with_me_query().count()

    if current_user.role == "admin":
        total_documents = Document.query.count()
        total_users = User.query.count()

        # Keep the existing admin dashboard behavior.
        my_documents_count = total_documents

    else:
        my_documents_count = Document.query.filter_by(
            owner_id=current_user.id
        ).count()

        total_documents = my_documents_count
        total_users = 0

    categories_count = visible_documents_query().with_entities(
        Document.category
    ).distinct().count()

    recent_documents = visible_documents_query().order_by(
        Document.uploaded_at.desc()
    ).limit(5).all()

    return render_template(
        "dashboard.html",
        total_documents=total_documents,
        total_users=total_users,
        my_documents_count=my_documents_count,
        shared_documents=shared_count,
        shared_documents_count=shared_count,
        categories_count=categories_count,
        recent_documents=recent_documents,
    )


# ---------------------------------------------------------
# Search Documents
# ---------------------------------------------------------

@pages_bp.route("/search")
@active_login_required
def search_documents():

    query_text = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    owner_name = request.args.get("owner", "").strip()

    documents_query = visible_documents_query()

    if query_text:
        documents_query = documents_query.filter(
            Document.title.ilike(f"%{query_text}%")
        )

    if category:
        documents_query = documents_query.filter(
            Document.category == category
        )

    if owner_name:
        documents_query = documents_query.join(
            User,
            Document.owner_id == User.id,
        ).filter(
            User.username.ilike(f"%{owner_name}%")
        )

    documents = documents_query.order_by(
        Document.uploaded_at.desc()
    ).all()

    categories = [
        row[0]
        for row in visible_documents_query().with_entities(
            Document.category
        ).distinct().order_by(
            Document.category
        ).all()
    ]

    return render_template(
        "search_documents.html",
        documents=documents,
        categories=categories,
        q=query_text,
        selected_category=category,
        owner_name=owner_name,
    )


# ---------------------------------------------------------
# Categories
# ---------------------------------------------------------

@pages_bp.route("/categories")
@active_login_required
def categories():

    category_counts = visible_documents_query().with_entities(
        Document.category,
        func.count(Document.id),
    ).group_by(
        Document.category
    ).order_by(
        Document.category
    ).all()

    return render_template(
        "categories.html",
        category_counts=category_counts,
    )


# ---------------------------------------------------------
# Activity Logs - Admin only
# ---------------------------------------------------------

@pages_bp.route("/activity-logs")
@roles_required("admin")
def activity_logs():

    logs = ActivityLog.query.order_by(
        ActivityLog.created_at.desc()
    ).limit(500).all()

    return render_template(
        "activity_logs.html",
        logs=logs,
    )


# ---------------------------------------------------------
# Manage Users - Admin only
# ---------------------------------------------------------

@pages_bp.route("/manage-users")
@roles_required("admin")
def manage_users():

    users = User.query.order_by(
        User.created_at.desc()
    ).all()

    return render_template(
        "manage_users.html",
        users=users,
    )


# ---------------------------------------------------------
# Activate / Deactivate User - Admin only
# ---------------------------------------------------------

@pages_bp.route(
    "/manage-users/<int:user_id>/status",
    methods=["POST"],
)
@roles_required("admin")
def change_user_status(user_id):

    user = db.session.get(User, user_id)

    if user is None:
        abort(404)

    # An administrator cannot change their own status here.
    if user.id == current_user.id:
        flash(
            "You cannot change your own account status.",
            "error",
        )
        return redirect(url_for("pages.manage_users"))

    # Prevent deactivating the last active administrator.
    if user.role == "admin" and user.is_active:
        active_admin_count = User.query.filter_by(
            role="admin",
            is_active=True,
        ).count()

        if active_admin_count <= 1:
            flash(
                "The last active administrator cannot be deactivated.",
                "error",
            )
            return redirect(url_for("pages.manage_users"))

    try:
        new_status = not user.is_active
        user.is_active = new_status

        db.session.add(
            ActivityLog(
                user_id=current_user.id,
                action="USER_STATUS_CHANGED",
                details=(
                    f"User {user.id} active status changed "
                    f"to {new_status}"
                ),
            )
        )

        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()

        flash(
            "Could not update user status. Please try again.",
            "error",
        )

        return redirect(url_for("pages.manage_users"))

    status_text = "activated" if user.is_active else "deactivated"

    flash(
        f"User {status_text} successfully.",
        "success",
    )

    return redirect(url_for("pages.manage_users"))
