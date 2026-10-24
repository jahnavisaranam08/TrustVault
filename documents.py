import re
import uuid
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
)
from flask_login import current_user, login_required
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.utils import secure_filename

from models import db, User, Document, DocumentShare, ActivityLog
from security import can_manage_document


documents_bp = Blueprint(
    "documents",
    __name__,
    url_prefix="/documents",
)


# ---------------------------------------------------------------------
# General security helpers
# ---------------------------------------------------------------------

def ensure_active_user():
    """Require an authenticated, active account."""
    if not current_user.is_authenticated:
        abort(401)

    if not current_user.is_active:
        abort(403)


def log_action(action, details=""):
    """Add an activity log entry to the current transaction."""
    db.session.add(
        ActivityLog(
            user_id=current_user.id,
            action=str(action)[:100],
            details=str(details)[:500],
        )
    )


def get_document_or_404(document_id):
    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    return document


def get_user_permission(document):
    """Return effective access: edit, read, or None."""
    if not current_user.is_authenticated:
        return None

    if not current_user.is_active:
        return None

    if current_user.role == "admin":
        return "edit"

    if document.owner_id == current_user.id:
        return "edit"

    share = DocumentShare.query.filter_by(
        document_id=document.id,
        user_id=current_user.id,
    ).first()

    if share is None or share.permission not in ("read", "edit"):
        return None

    owner = db.session.get(User, document.owner_id)

    if owner is None or not owner.is_active:
        return None

    return share.permission


def get_upload_folder():
    configured_folder = current_app.config.get("UPLOAD_FOLDER")

    if not configured_folder:
        raise RuntimeError("UPLOAD_FOLDER is not configured.")

    folder = Path(configured_folder).resolve()
    folder.mkdir(parents=True, exist_ok=True)

    return folder


def allowed_extension(filename):
    if not filename or "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()
    configured = current_app.config.get("ALLOWED_EXTENSIONS", set())

    allowed = {
        str(item).lower().lstrip(".")
        for item in configured
    }

    return bool(allowed) and extension in allowed


def is_safe_stored_filename(filename):
    """Allow UUID-based stored filenames only."""
    if not filename or len(filename) > 100:
        return False

    return bool(
        re.fullmatch(
            r"[0-9a-f]{32}\.[a-z0-9]{1,10}",
            filename,
        )
    )


def get_safe_file_path(document, upload_folder=None):
    if not is_safe_stored_filename(document.stored_filename):
        current_app.logger.warning(
            "Unsafe stored filename for document ID %s",
            document.id,
        )
        abort(404)

    folder = upload_folder or get_upload_folder()
    resolved_folder = folder.resolve()

    file_path = (resolved_folder / document.stored_filename).resolve()

    try:
        file_path.relative_to(resolved_folder)
    except ValueError:
        abort(404)

    if not file_path.is_file():
        abort(404)

    return file_path


def cleanup_file(file_path):
    try:
        file_path.unlink(missing_ok=True)
    except OSError:
        current_app.logger.exception(
            "Could not clean up a failed upload."
        )


def get_max_upload_size():
    return int(
        current_app.config.get(
            "MAX_CONTENT_LENGTH",
            16 * 1024 * 1024,
        )
    )


def validate_manage_access(document):
    """Only the owner or an active admin can manage a document."""
    if not can_manage_document(document):
        abort(403)


# ---------------------------------------------------------------------
# My Documents
# ---------------------------------------------------------------------

@documents_bp.route("/")
@login_required
def my_documents():
    ensure_active_user()

    if current_user.role == "admin":
        owned = Document.query.order_by(
            Document.uploaded_at.desc()
        ).all()
    else:
        owned = Document.query.filter_by(
            owner_id=current_user.id
        ).order_by(
            Document.uploaded_at.desc()
        ).all()

    shares = DocumentShare.query.filter_by(
        user_id=current_user.id
    ).all()

    shared_ids = [share.document_id for share in shares]

    if shared_ids:
        shared_candidates = Document.query.filter(
            Document.id.in_(shared_ids)
        ).order_by(
            Document.uploaded_at.desc()
        ).all()
    else:
        shared_candidates = []

    owned_ids = {document.id for document in owned}

    shared = [
        document
        for document in shared_candidates
        if document.id not in owned_ids
        and get_user_permission(document) in ("read", "edit")
    ]

    return render_template(
        "my_documents.html",
        documents=owned,
        shared_documents=shared,
    )


# ---------------------------------------------------------------------
# Upload Document
# ---------------------------------------------------------------------

@documents_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    ensure_active_user()

    if request.method == "GET":
        return render_template("upload.html")

    # upload.html uses name="file".
    uploaded_file = request.files.get("file")

    title = request.form.get("title", "").strip()
    category = (
        request.form.get("category", "General").strip()
        or "General"
    )

    if not uploaded_file or not uploaded_file.filename:
        flash("Please choose a file.", "error")
        return redirect(
            request.url
        )

    if not title or len(title) > 200 or len(category) > 80:
        flash("Enter a valid title and category.", "error")
        return redirect(request.url)

    original_name = secure_filename(uploaded_file.filename)

    if not original_name or not allowed_extension(original_name):
        flash("This file type or filename is not allowed.", "error")
        return redirect(request.url)

    max_size = get_max_upload_size()

    if (
        uploaded_file.content_length is not None
        and uploaded_file.content_length > max_size
    ):
        abort(413)

    extension = original_name.rsplit(".", 1)[1].lower()
    stored_name = f"{uuid.uuid4().hex}.{extension}"

    upload_folder = get_upload_folder()
    saved_path = upload_folder / stored_name

    try:
        uploaded_file.save(str(saved_path))

        if not saved_path.is_file():
            raise OSError("Uploaded file was not saved.")

        file_size = saved_path.stat().st_size

        if file_size == 0:
            cleanup_file(saved_path)
            flash("Empty files are not allowed.", "error")
            return redirect(request.url)

        if file_size > max_size:
            cleanup_file(saved_path)
            abort(413)

        document = Document(
            title=title,
            stored_filename=stored_name,
            category=category,
            owner_id=current_user.id,
        )

        db.session.add(document)
        db.session.flush()

        log_action(
            "DOCUMENT_UPLOAD",
            f"Uploaded document {document.id}",
        )

        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()
        cleanup_file(saved_path)

        current_app.logger.exception(
            "Document upload database operation failed."
        )
        flash("Upload failed. Please try again.", "error")
        return redirect(request.url)

    except OSError:
        db.session.rollback()
        cleanup_file(saved_path)

        current_app.logger.exception("Document upload failed.")
        flash("Upload failed. Please try again.", "error")
        return redirect(request.url)

    except Exception:
        db.session.rollback()
        cleanup_file(saved_path)
        raise

    flash("Document uploaded successfully.", "success")
    return redirect(
        request.url_root.rstrip("/") + "/documents/"
    )


# ---------------------------------------------------------------------
# Secure Download
# ---------------------------------------------------------------------

@documents_bp.route("/<int:document_id>/download", methods=["GET"])
@login_required
def download(document_id):
    ensure_active_user()

    document = get_document_or_404(document_id)
    permission = get_user_permission(document)

    if permission not in ("read", "edit"):
        abort(403)

    upload_folder = get_upload_folder()
    file_path = get_safe_file_path(document, upload_folder)

    # Preserve the actual stored file extension.
    original_extension = Path(
        document.stored_filename
    ).suffix.lower()

    safe_title = secure_filename(document.title) or "document"

    # Add .pdf, .docx, etc. if the title has no extension.
    if original_extension and not safe_title.lower().endswith(
        original_extension
    ):
        download_name = f"{safe_title}{original_extension}"
    else:
        download_name = safe_title

    try:
        log_action(
            "DOCUMENT_DOWNLOAD",
            f"Downloaded document {document.id}",
        )
        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()

        current_app.logger.exception(
            "Could not record document download activity."
        )
        abort(500)

    return send_from_directory(
        str(upload_folder),
        file_path.name,
        as_attachment=True,
        download_name=download_name,
    )


# ---------------------------------------------------------------------
# Share / Update Permissions
# ---------------------------------------------------------------------

@documents_bp.route(
    "/<int:document_id>/share",
    methods=["GET", "POST"],
)
@login_required
def share(document_id):
    ensure_active_user()

    document = get_document_or_404(document_id)
    validate_manage_access(document)

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        permission = (
            request.form.get("permission", "read").strip().lower()
        )

        if not email or len(email) > 120:
            flash("Enter a valid user email.", "error")
            return redirect(
                request.url
            )

        if permission not in ("read", "edit"):
            abort(400)

        user = User.query.filter_by(email=email).first()

        if user is None or not user.is_active:
            flash("Active user not found.", "error")

        elif user.id == document.owner_id:
            flash("The owner already has access.", "error")

        elif user.role == "admin":
            flash("Admin accounts do not need document shares.", "error")

        else:
            try:
                existing = DocumentShare.query.filter_by(
                    document_id=document.id,
                    user_id=user.id,
                ).first()

                if existing:
                    existing.permission = permission
                    action = "PERMISSION_UPDATED"
                else:
                    db.session.add(
                        DocumentShare(
                            document_id=document.id,
                            user_id=user.id,
                            permission=permission,
                        )
                    )
                    action = "PERMISSION_GRANTED"

                log_action(
                    action,
                    f"Document {document.id}, user {user.id}",
                )

                db.session.commit()
                flash("Document access saved.", "success")

            except SQLAlchemyError:
                db.session.rollback()

                current_app.logger.exception(
                    "Could not save document permissions."
                )
                flash(
                    "Could not save access. Please try again.",
                    "error",
                )

        return redirect(request.url)

    shares = DocumentShare.query.filter_by(
        document_id=document.id
    ).all()

    return render_template(
        "permissions.html",
        document=document,
        shares=shares,
    )


# ---------------------------------------------------------------------
# Revoke Document Access
# ---------------------------------------------------------------------

@documents_bp.route(
    "/<int:document_id>/revoke/<int:share_id>",
    methods=["POST"],
)
@login_required
def revoke(document_id, share_id):
    ensure_active_user()

    document = get_document_or_404(document_id)
    validate_manage_access(document)

    share_record = db.session.get(DocumentShare, share_id)

    if (
        share_record is None
        or share_record.document_id != document.id
    ):
        abort(404)

    try:
        db.session.delete(share_record)

        log_action(
            "PERMISSION_REVOKED",
            f"Document {document.id}, share {share_id}",
        )

        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()

        current_app.logger.exception(
            "Could not revoke document permission."
        )
        flash(
            "Could not revoke access. Please try again.",
            "error",
        )
        return redirect(request.url_root.rstrip("/") +
                        f"/documents/{document.id}/share")

    flash("Document access revoked.", "success")
    return redirect(
        request.url_root.rstrip("/") +
        f"/documents/{document.id}/share"
    )


# ---------------------------------------------------------------------
# Delete Document
# ---------------------------------------------------------------------

@documents_bp.route(
    "/<int:document_id>/delete",
    methods=["POST"],
)
@login_required
def delete(document_id):
    ensure_active_user()

    document = get_document_or_404(document_id)
    validate_manage_access(document)

    upload_folder = get_upload_folder()
    file_path = get_safe_file_path(document, upload_folder)

    try:
        log_action(
            "DOCUMENT_DELETE",
            f"Deleted document {document.id}",
        )

        db.session.delete(document)
        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()

        current_app.logger.exception(
            "Could not delete document database record."
        )
        flash(
            "Could not delete the document. Please try again.",
            "error",
        )
        return redirect(
            request.url_root.rstrip("/") + "/documents/"
        )

    try:
        file_path.unlink(missing_ok=True)

    except OSError:
        current_app.logger.exception(
            "Database record deleted, but the physical file remains."
        )
        flash(
            "Document record deleted, but its file could not be removed. "
            "Contact the administrator.",
            "warning",
        )
        return redirect(
            request.url_root.rstrip("/") + "/documents/"
        )

    flash("Document deleted.", "success")
    return redirect(
        request.url_root.rstrip("/") + "/documents/"
    )
