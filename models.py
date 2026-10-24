
from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


def utc_now():
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


# --------------------------------------------------
# User Model
# --------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False,
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False,
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    # Keep the existing role default for database compatibility.
    role = db.Column(
        db.String(20),
        nullable=False,
        default="owner",
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=utc_now,
    )

    owned_documents = db.relationship(
        "Document",
        back_populates="owner",
        cascade="all, delete-orphan",
    )

    shares = db.relationship(
        "DocumentShare",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="DocumentShare.user_id",
    )


# --------------------------------------------------
# Document Model
# --------------------------------------------------

class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    title = db.Column(
        db.String(200),
        nullable=False,
    )

    stored_filename = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
    )

    category = db.Column(
        db.String(80),
        nullable=False,
        default="General",
    )

    uploaded_at = db.Column(
        db.DateTime(timezone=True),
        default=utc_now,
    )

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
    )

    owner = db.relationship(
        "User",
        back_populates="owned_documents",
    )

    shares = db.relationship(
        "DocumentShare",
        back_populates="document",
        cascade="all, delete-orphan",
    )


# --------------------------------------------------
# Document Share Model
# --------------------------------------------------

class DocumentShare(db.Model):
    __tablename__ = "document_shares"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("documents.id"),
        nullable=False,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
    )

    permission = db.Column(
        db.String(10),
        nullable=False,
        default="read",
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=utc_now,
    )

    document = db.relationship(
        "Document",
        back_populates="shares",
    )

    user = db.relationship(
        "User",
        back_populates="shares",
        foreign_keys=[user_id],
    )

    __table_args__ = (
        db.UniqueConstraint(
            "document_id",
            "user_id",
            name="unique_document_user_share",
        ),
        db.CheckConstraint(
            "permission IN ('read', 'edit')",
            name="valid_document_permission",
        ),
    )


# --------------------------------------------------
# Activity Log Model
# --------------------------------------------------

class ActivityLog(db.Model):
    __tablename__ = "activity_logs"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True,
    )

    action = db.Column(
        db.String(100),
        nullable=False,
    )

    details = db.Column(
        db.String(500),
        nullable=False,
        default="",
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=utc_now,
    )

    user = db.relationship(
        "User",
        backref="activity_logs",
    )
