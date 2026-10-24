
from functools import wraps

from flask import abort
from flask_login import current_user, login_required


def roles_required(*allowed_roles):
    """
    Allow access only to authenticated, active users
    whose role is included in allowed_roles.

    Example:
        @roles_required("admin")
    """

    def decorator(view_function):
        @wraps(view_function)
        @login_required
        def wrapped(*args, **kwargs):
            # Reject inactive accounts.
            if not current_user.is_active:
                abort(403)

            # Reject users without the required role.
            if current_user.role not in allowed_roles:
                abort(403)

            return view_function(*args, **kwargs)

        return wrapped

    return decorator


def can_manage_document(document):
    """
    Only an active authenticated admin or document owner
    can manage a document.

    Managing includes actions such as sharing, revoking access,
    and deleting, provided the calling route uses this check.
    """

    if not current_user.is_authenticated:
        return False

    if not current_user.is_active:
        return False

    if current_user.role == "admin":
        return True

    return document.owner_id == current_user.id
