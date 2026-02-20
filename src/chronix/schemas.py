# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Tyrrell Brewster

"""
Chronix API Schemas

Pydantic models for request/response validation.
Separates API concerns from database models.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from enum import Enum


# === Enums (mirror the SQLAlchemy enums) ===

class SystemModification(str, Enum):
    UNKNOWN = "Unknown"
    NO = "No"
    YES_INTENDED = "Yes-Intended"
    YES_UNINTENDED = "Yes-Unintended"


class ActionType(str, Enum):
    DISCOVERY = "Discovery"
    EXPLOITATION = "Exploitation"
    CREDENTIAL_ACCESS = "Credential Access"
    LATERAL_MOVEMENT = "Lateral Movement"
    PERSISTENCE = "Persistence"
    CLEANUP = "Cleanup"
    ADMIN_NOTES = "Admin/Notes"


class EngagementStatus(str, Enum):
    PLANNING = "Planning"
    ACTIVE = "Active"
    PAUSED = "Paused"
    COMPLETED = "Completed"
    ARCHIVED = "Archived"


# === Operator Schemas ===

class OperatorCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    display_name: str = Field(..., min_length=1, max_length=128)


class OperatorResponse(BaseModel):
    id: str
    username: str
    display_name: str
    created_at: datetime
    last_seen: datetime
    is_active: bool
    
    class Config:
        from_attributes = True


class OperatorPresenceResponse(BaseModel):
    """Who's currently active in an engagement"""
    operator_id: str
    username: str
    display_name: str
    last_heartbeat: datetime
    current_view: Optional[str] = None
    current_note_page_id: Optional[str] = None


# === Engagement Schemas ===

class EngagementCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    client_name: Optional[str] = Field(None, max_length=256)
    description: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None


class EngagementUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    client_name: Optional[str] = Field(None, max_length=256)
    description: Optional[str] = None
    status: Optional[EngagementStatus] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None


class EngagementResponse(BaseModel):
    id: str
    name: str
    client_name: Optional[str]
    description: Optional[str]
    status: EngagementStatus
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    entry_count: int = 0
    
    class Config:
        from_attributes = True


class EngagementListResponse(BaseModel):
    """Paginated list of engagements"""
    engagements: List[EngagementResponse]
    total: int
    page: int
    page_size: int


# === Timeline Entry Schemas ===

class TimelineEntryCreate(BaseModel):
    """Schema for creating a new timeline entry"""
    # Timing (start_time auto-filled if not provided)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Network context
    source_ip: Optional[str] = Field(None, max_length=45)
    destination_ip: Optional[str] = Field(None, max_length=45)
    destination_port: Optional[str] = Field(None, max_length=16)
    destination_system: Optional[str] = Field(None, max_length=256)
    
    # Pivoting
    pivot_ip: Optional[str] = Field(None, max_length=45)
    pivot_port: Optional[str] = Field(None, max_length=32)
    
    # Target
    url: Optional[str] = None
    
    # Action details
    tool_app: Optional[str] = Field(None, max_length=128)
    command: Optional[str] = None
    description: Optional[str] = None
    output: Optional[str] = None
    result: Optional[str] = None
    
    # Metadata
    system_modification: SystemModification = SystemModification.UNKNOWN
    action_type: Optional[ActionType] = None
    comments: Optional[str] = None


class TimelineEntryUpdate(BaseModel):
    """Schema for updating a timeline entry - all fields editable for typo correction"""
    # Timing
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Network context
    source_ip: Optional[str] = Field(None, max_length=45)
    destination_ip: Optional[str] = Field(None, max_length=45)
    destination_port: Optional[str] = Field(None, max_length=16)
    destination_system: Optional[str] = Field(None, max_length=256)
    
    # Pivoting
    pivot_ip: Optional[str] = Field(None, max_length=45)
    pivot_port: Optional[str] = Field(None, max_length=32)
    
    # Target
    url: Optional[str] = None
    
    # Action details
    tool_app: Optional[str] = Field(None, max_length=128)
    command: Optional[str] = None
    description: Optional[str] = None
    output: Optional[str] = None
    result: Optional[str] = None
    
    # Metadata
    system_modification: Optional[SystemModification] = None
    action_type: Optional[ActionType] = None
    comments: Optional[str] = None


class TimelineEntryResponse(BaseModel):
    """Full timeline entry for API responses"""
    id: str
    engagement_id: str
    operator_id: str
    operator_name: str  # Denormalized for convenience
    
    # Timing
    start_time: datetime
    end_time: Optional[datetime]
    
    # Network context
    source_ip: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[str]
    destination_system: Optional[str]
    
    # Pivoting
    pivot_ip: Optional[str]
    pivot_port: Optional[str]
    
    # Target
    url: Optional[str]
    
    # Action details
    tool_app: Optional[str]
    command: Optional[str]
    description: Optional[str]
    output: Optional[str]
    result: Optional[str]
    
    # Metadata
    system_modification: SystemModification
    action_type: Optional[ActionType]
    comments: Optional[str]
    
    # Audit
    created_at: datetime
    updated_at: datetime
    is_deleted: bool
    
    class Config:
        from_attributes = True


class TimelineFilter(BaseModel):
    """Query parameters for filtering timeline"""
    operator_id: Optional[str] = None
    action_type: Optional[ActionType] = None
    tool_app: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_system: Optional[str] = None
    start_after: Optional[datetime] = None
    start_before: Optional[datetime] = None
    search: Optional[str] = None  # Full-text search across fields


class TimelineListResponse(BaseModel):
    """Paginated timeline with metadata"""
    entries: List[TimelineEntryResponse]
    total: int
    page: int
    page_size: int
    # Quick stats
    unique_operators: int
    unique_targets: int


# =============================================================================
# LEGACY SCHEMAS - Running Notes
# =============================================================================
# These schemas are retained for backward compatibility only.
# - No active API endpoints use these schemas
# - Replaced by NotePageCreate, NotePageUpdate, NotePageResponse
# - Kept in case future migration tooling needs them
# - DO NOT use in new code; use Note Page schemas instead
# =============================================================================

class RunningNoteUpdate(BaseModel):
    """LEGACY: Update shared running notes (creates new version)"""
    content: str


class RunningNoteResponse(BaseModel):
    """LEGACY: Running note response schema"""
    id: str
    engagement_id: str
    content: str
    version: int
    edited_by: Optional[str]
    editor_name: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True


class RunningNoteHistoryResponse(BaseModel):
    """LEGACY: List of note versions"""
    versions: List[RunningNoteResponse]
    current_version: int


# =============================================================================
# Note Page Schemas (Active)
# =============================================================================

class NotePageCreate(BaseModel):
    """Create a new note page"""
    title: str = Field(..., min_length=1, max_length=256)
    content: str = ""


class NotePageUpdate(BaseModel):
    """Update a note page (title, content, or order)"""
    title: Optional[str] = Field(None, min_length=1, max_length=256)
    content: Optional[str] = None
    order_index: Optional[int] = None


class NotePageResponse(BaseModel):
    """Full note page for API responses"""
    id: str
    engagement_id: str
    title: str
    content: str
    order_index: int
    version: int
    created_at: datetime
    updated_at: datetime
    edited_by: Optional[str] = None
    editor_name: Optional[str] = None
    
    class Config:
        from_attributes = True


class NotePageListResponse(BaseModel):
    """List of note pages for an engagement"""
    pages: List[NotePageResponse]
    total: int


# CHRONIX-009 FIX: Typed Pydantic model for page order items
class PageOrderItem(BaseModel):
    """Individual page order entry with validated fields"""
    id: str = Field(..., min_length=1, max_length=64)
    order_index: int = Field(..., ge=0, le=10000)


class NotePageReorderRequest(BaseModel):
    """Request to reorder note pages"""
    page_orders: List[PageOrderItem] = Field(..., max_length=100)


# === CSV Import/Export ===

class CSVImportResult(BaseModel):
    """Result of CSV import operation"""
    success: bool
    imported_count: int
    error_count: int
    errors: List[str]


class CSVExportRequest(BaseModel):
    """Options for CSV export"""
    include_deleted: bool = False
    filter: Optional[TimelineFilter] = None


# === WebSocket Messages ===
# NOTE: These schemas document the WebSocket message formats sent by manager.broadcast().
# They are not used in runtime validation but serve as API documentation for frontend developers.

class TimelineUpdateMessage(BaseModel):
    """Broadcast when timeline changes"""
    type: str = "timeline_update"
    action: str  # "create", "update", "delete"
    entry: TimelineEntryResponse


class NotePageUpdateMessage(BaseModel):
    """Broadcast when a note page changes"""
    type: str = "notepage_update"
    action: str  # "create", "update", "delete", "reorder"
    page_id: str
    page: Optional[NotePageResponse] = None
    edited_by: str
    editor_name: str


# === Note Attachment Schemas ===

class NoteAttachmentResponse(BaseModel):
    """Response for uploaded attachment"""
    id: str
    note_page_id: str
    engagement_id: str
    filename: str
    # CHRONIX-010 FIX: stored_filename removed — internal implementation detail
    mime_type: str
    file_size: int
    alt_text: Optional[str] = ""
    created_at: datetime
    uploaded_by: Optional[str] = None
    # URL path for accessing the image
    url: str
    
    class Config:
        from_attributes = True


class NoteAttachmentListResponse(BaseModel):
    """List of attachments for a note page"""
    attachments: List[NoteAttachmentResponse]
    total: int


# === Export Schemas ===

class NoteExportOptions(BaseModel):
    """Options for markdown export"""
    include_frontmatter: bool = True
    include_attachments: bool = True
