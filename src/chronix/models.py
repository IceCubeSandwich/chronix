# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Tyrrell Brewster

"""
Chronix Data Models

Core entities:
- User: Authenticated user with role-based access control
- Engagement: A red team operation/assessment
- TimelineEntry: One logged action in the timeline
- RunningNote: Versioned shared notes per engagement (legacy, being replaced by NotePages)
- NotePage: Individual note pages with tabs
- Operator: Legacy user identity (kept for backwards compatibility)
- UserEngagementAccess: Many-to-many user<->engagement permissions

Design decisions:
- SQLite for portability and self-hosting
- Append-only timeline (soft delete only, preserves audit trail)
- UUIDs for entries to support multi-operator sync
- Timestamps stored as UTC, exported as local
- Argon2 password hashing (configured in security.py)
- Role-based access: Admin, Operator, ReadOnly
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List
from sqlalchemy import (
    Column, String, Text, DateTime, ForeignKey, Integer, 
    Boolean, Enum as SQLEnum, Index, create_engine, Table
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.sql import func
import uuid

Base = declarative_base()


# === Enums ===

class UserRole(str, Enum):
    """User roles for RBAC"""
    ADMIN = "admin"
    OPERATOR = "operator"
    READONLY = "readonly"


class SystemModification(str, Enum):
    """Did this action modify the target system?"""
    UNKNOWN = "Unknown"
    NO = "No"
    YES_INTENDED = "Yes-Intended"
    YES_UNINTENDED = "Yes-Unintended"


class ActionType(str, Enum):
    """Soft categorization for filtering timeline entries"""
    DISCOVERY = "Discovery"
    EXPLOITATION = "Exploitation"
    CREDENTIAL_ACCESS = "Credential Access"
    LATERAL_MOVEMENT = "Lateral Movement"
    PERSISTENCE = "Persistence"
    CLEANUP = "Cleanup"
    ADMIN_NOTES = "Admin/Notes"


class EngagementStatus(str, Enum):
    """Engagement lifecycle states"""
    PLANNING = "Planning"
    ACTIVE = "Active"
    PAUSED = "Paused"
    COMPLETED = "Completed"
    ARCHIVED = "Archived"


# === Association Tables ===

user_engagement_access = Table(
    'user_engagement_access',
    Base.metadata,
    Column('user_id', String(36), ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    Column('engagement_id', String(36), ForeignKey('engagements.id', ondelete='CASCADE'), primary_key=True),
    Column('created_at', DateTime, default=func.now()),
)


# === Models ===

class User(Base):
    """
    Authenticated user with role-based access control.
    
    Security notes:
    - Password is Argon2id hashed (see security.py)
    - Role determines base permissions
    - Engagement access is explicit (except for Admin who has all)
    """
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    display_name = Column(String(128), nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.OPERATOR, nullable=False)
    
    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    last_login = Column(DateTime, nullable=True)
    
    # Password change tracking (for forced password change)
    password_changed_at = Column(DateTime, default=func.now())
    
    # Relationships
    engagements = relationship(
        "Engagement",
        secondary=user_engagement_access,
        back_populates="users",
    )
    timeline_entries = relationship("TimelineEntry", back_populates="user")
    
    def __repr__(self):
        return f"<User {self.username} ({self.role.value})>"


class Operator(Base):
    """
    Legacy operator model - kept for backwards compatibility.
    New installations should use User model instead.
    
    Migration path: Create User records for existing Operators,
    then update foreign keys.
    """
    __tablename__ = "operators"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    display_name = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True)
    
    # Link to new User model (for migration)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=True)
    
    # Relationships
    legacy_timeline_entries = relationship("TimelineEntry", back_populates="operator", foreign_keys="TimelineEntry.operator_id")
    
    def __repr__(self):
        return f"<Operator {self.username}>"


class Engagement(Base):
    """
    A red team engagement/assessment.
    Container for timeline entries and running notes.
    
    Access control: Users must have explicit access via user_engagement_access
    table, except Admins who have implicit access to all engagements.
    """
    __tablename__ = "engagements"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(256), nullable=False)
    client_name = Column(String(256))
    description = Column(Text)
    status = Column(SQLEnum(EngagementStatus), default=EngagementStatus.PLANNING)
    
    # Date range
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    
    # Creator tracking
    created_by = Column(String(36), ForeignKey('users.id'), nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    users = relationship(
        "User",
        secondary=user_engagement_access,
        back_populates="engagements",
    )
    creator = relationship("User", foreign_keys=[created_by])
    timeline_entries = relationship("TimelineEntry", back_populates="engagement", 
                                    order_by="TimelineEntry.start_time")
    # LEGACY: Retained for database compatibility. Use note_pages for new features.
    running_notes = relationship("RunningNote", back_populates="engagement",
                                 order_by="RunningNote.version.desc()")
    # Active: Multi-tab note pages (replaced RunningNote)
    note_pages = relationship("NotePage", back_populates="engagement",
                              cascade="all, delete-orphan",
                              order_by="NotePage.order_index")
    
    def __repr__(self):
        return f"<Engagement {self.name}>"


class TimelineEntry(Base):
    """
    One action in the operational timeline.
    This is the core of Chronix - structured logging of operator actions.
    
    Fields match the required CSV export format exactly.
    """
    __tablename__ = "timeline_entries"
    
    # Identity
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id = Column(String(36), ForeignKey("engagements.id"), nullable=False, index=True)
    
    # User reference (new auth system)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    # Legacy operator reference (for backwards compatibility)
    operator_id = Column(String(36), ForeignKey("operators.id"), nullable=True, index=True)
    
    # Timing
    start_time = Column(DateTime, nullable=False, default=func.now(), index=True)
    end_time = Column(DateTime)
    
    # Network context - where are we attacking from/to
    source_ip = Column(String(45))  # IPv6 max length
    destination_ip = Column(String(45))
    destination_port = Column(String(16))  # Can be "445" or "445,139" etc.
    destination_system = Column(String(256))  # Hostname or description
    
    # Pivoting context
    pivot_ip = Column(String(45))
    pivot_port = Column(String(32))  # Supports "80>1480" notation
    
    # Target URL if web-based
    url = Column(Text)
    
    # What tool/technique was used
    tool_app = Column(String(128))
    command = Column(Text)  # Full command, can be long
    
    # What happened
    description = Column(Text)  # What you were trying to do
    output = Column(Text)  # Key output, can be very long
    result = Column(Text)  # What actually happened
    
    # Impact tracking
    system_modification = Column(
        SQLEnum(SystemModification), 
        default=SystemModification.UNKNOWN
    )
    
    # Categorization and notes
    action_type = Column(SQLEnum(ActionType))
    comments = Column(Text)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    is_deleted = Column(Boolean, default=False)  # Soft delete only
    
    # Relationships
    engagement = relationship("Engagement", back_populates="timeline_entries")
    user = relationship("User", back_populates="timeline_entries")
    operator = relationship("Operator", back_populates="legacy_timeline_entries", foreign_keys=[operator_id])
    
    # Indexes for common queries
    __table_args__ = (
        Index("idx_timeline_engagement_time", "engagement_id", "start_time"),
        Index("idx_timeline_user", "engagement_id", "user_id"),
        Index("idx_timeline_operator", "engagement_id", "operator_id"),
        Index("idx_timeline_destination", "engagement_id", "destination_ip"),
        Index("idx_timeline_tool", "engagement_id", "tool_app"),
    )
    
    @property
    def actor_name(self) -> str:
        """Get display name of who created this entry"""
        if self.user:
            return self.user.display_name
        if self.operator:
            return self.operator.display_name
        return "Unknown"
    
    def __repr__(self):
        return f"<TimelineEntry {self.id[:8]} - {self.tool_app or 'no tool'}>"


class RunningNote(Base):
    """
    LEGACY MODEL - Retained for database compatibility only.
    
    Original shared running notes for an engagement.
    Versioned - every save creates a new version.
    Was used for: creds, hosts, hypotheses, team context.
    
    MIGRATION STATUS:
    - Replaced by NotePage model which provides multi-tab support
    - No active API endpoints use this model
    - Table retained to preserve historical data and enable future migration
    - New code should use NotePage instead
    
    DO NOT add new features or endpoints using this model.
    """
    __tablename__ = "running_notes"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id = Column(String(36), ForeignKey("engagements.id"), nullable=False, index=True)
    
    # Content (Markdown)
    content = Column(Text, nullable=False, default="")
    
    # Versioning
    version = Column(Integer, nullable=False, default=1)
    edited_by = Column(String(36), ForeignKey("operators.id"))
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    engagement = relationship("Engagement", back_populates="running_notes")
    editor = relationship("Operator")
    
    __table_args__ = (
        Index("idx_notes_engagement_version", "engagement_id", "version"),
    )
    
    def __repr__(self):
        return f"<RunningNote v{self.version} for {self.engagement_id[:8]}>"


class NotePage(Base):
    """
    Feature #1: Individual note pages within an engagement.
    Supports multiple tabs for organizing notes.
    """
    __tablename__ = "note_pages"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id = Column(String(36), ForeignKey("engagements.id"), nullable=False, index=True)
    
    # Page info
    title = Column(String(256), nullable=False)  # e.g., "Recon", "Domain Analysis"
    content = Column(Text, default="")
    
    # Ordering for tabs
    order_index = Column(Integer, default=0)
    
    # Versioning (simple version counter for conflict detection)
    version = Column(Integer, default=1)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Last editor tracking
    edited_by = Column(String(36), ForeignKey("operators.id"))
    
    # Relationships
    engagement = relationship("Engagement", back_populates="note_pages")
    editor = relationship("Operator")
    
    __table_args__ = (
        Index("idx_notepage_engagement", "engagement_id"),
        Index("idx_notepage_order", "engagement_id", "order_index"),
    )
    
    def __repr__(self):
        return f"<NotePage '{self.title}' for {self.engagement_id[:8]}>"


class OperatorPresence(Base):
    """
    Track which operators are currently active in an engagement.
    Updated via heartbeat, cleaned up on disconnect.
    """
    __tablename__ = "operator_presence"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    engagement_id = Column(String(36), ForeignKey("engagements.id"), nullable=False)
    operator_id = Column(String(36), ForeignKey("operators.id"), nullable=False)
    last_heartbeat = Column(DateTime, default=func.now())
    
    # What are they looking at?
    current_view = Column(String(64))  # "timeline", "notes", etc.
    # Which note page are they on? (for Feature #1)
    current_note_page_id = Column(String(36))
    
    __table_args__ = (
        Index("idx_presence_engagement", "engagement_id"),
    )


class NoteAttachment(Base):
    """
    Attachments (images) for note pages.
    Stored on disk, tracked in DB for note association.
    """
    __tablename__ = "note_attachments"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    note_page_id = Column(String(36), ForeignKey("note_pages.id", ondelete="CASCADE"), nullable=False, index=True)
    engagement_id = Column(String(36), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # File info
    filename = Column(String(256), nullable=False)  # Original filename (sanitized)
    stored_filename = Column(String(256), nullable=False)  # On-disk filename (unique)
    mime_type = Column(String(64), nullable=False)  # image/png, image/jpeg, etc.
    file_size = Column(Integer, nullable=False)  # Size in bytes
    
    # Metadata
    alt_text = Column(String(256), default="")  # Optional alt text
    created_at = Column(DateTime, default=func.now())
    uploaded_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    
    # Relationships
    note_page = relationship("NotePage", backref="attachments")
    engagement = relationship("Engagement")
    uploader = relationship("User")
    
    __table_args__ = (
        Index("idx_attachment_note", "note_page_id"),
        Index("idx_attachment_engagement", "engagement_id"),
    )
    
    def __repr__(self):
        return f"<NoteAttachment {self.filename} for note {self.note_page_id[:8]}>"


# === Database Setup ===

def get_engine(db_path: str = "chronix.db"):
    """Create database engine"""
    return create_engine(f"sqlite:///{db_path}", echo=False)


def get_session(engine):
    """Create a session factory"""
    Session = sessionmaker(bind=engine)
    return Session()


def init_db(db_path: str = "chronix.db"):
    """Initialize the database, creating all tables"""
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
    return engine


# === CSV Export Format ===

# Exact column order for CSV export (matches spec)
CSV_COLUMNS = [
    "start_time",
    "end_time", 
    "operator_name",
    "source_ip",
    "destination_ip",
    "destination_port",
    "destination_system",
    "pivot_ip",
    "pivot_port",
    "url",
    "tool_app",
    "command",
    "description",
    "output",
    "result",
    "system_modification",
    "comments"
]


def format_datetime_for_export(dt: Optional[datetime]) -> str:
    """Format datetime as YYYYMMDD_HHMMSS for CSV export"""
    if dt is None:
        return ""
    return dt.strftime("%Y%m%d_%H%M%S")


if __name__ == "__main__":
    # Quick test: create tables
    engine = init_db("test_chronix.db")
    print("Database initialized successfully")
    print(f"Tables created: {Base.metadata.tables.keys()}")
