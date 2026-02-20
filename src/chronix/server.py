# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Tyrrell Brewster

"""Chronix API Server"""

import csv
import io
import os
import re
import stat
import zipfile
from datetime import datetime, timedelta
from typing import Optional, List
from contextlib import asynccontextmanager
from pathlib import Path
import uuid
import mimetypes

from fastapi import (
    FastAPI, HTTPException, Depends, Query, WebSocket, 
    WebSocketDisconnect, UploadFile, File, Request, Response, status
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, or_, distinct
from sqlalchemy.orm import Session, joinedload

from .models import (
    init_db,
    User, Operator, Engagement, TimelineEntry, NotePage, OperatorPresence, NoteAttachment,
    UserRole as DBUserRole,
    SystemModification as DBSystemModification,
    ActionType as DBActionType,
    EngagementStatus as DBEngagementStatus,
    user_engagement_access,
    CSV_COLUMNS, format_datetime_for_export
)
from .schemas import (
    OperatorCreate, OperatorResponse, OperatorPresenceResponse,
    EngagementUpdate, EngagementResponse,
    TimelineEntryCreate, TimelineEntryUpdate, TimelineEntryResponse, TimelineListResponse,
    NotePageCreate, NotePageUpdate, NotePageResponse, NotePageListResponse, NotePageReorderRequest,
    NoteAttachmentResponse, NoteAttachmentListResponse,
    CSVImportResult, SystemModification, ActionType, EngagementStatus
)
from .security import (
    SecurityConfig, init_security,
    UserRole, Permission, ROLE_PERMISSIONS,
    hash_password, verify_password, password_needs_rehash,
    SessionData, session_store, generate_csrf_token,
    check_login_rate_limit, check_write_rate_limit,
    sanitize_markdown, sanitize_plain_text,
    get_current_session,
    require_permission,
    set_session_cookie, clear_session_cookie,
    get_security_headers, get_cors_origins, get_client_ip,
    UserCreate, UserUpdate, PasswordChange, LoginRequest, LoginResponse, UserResponse,
    login_rate_limiter, write_rate_limiter,
)
from .core.security.filesystem import (
    secure_resolve, secure_serve_path, secure_open,
    sanitize_content_disposition,
)

DATABASE_PATH = os.environ.get("CHRONIX_DB_PATH", "chronix.db")
ATTACHMENTS_PATH = os.environ.get("CHRONIX_ATTACHMENTS_PATH", "attachments")
MAX_ATTACHMENT_SIZE = int(os.environ.get("CHRONIX_MAX_ATTACHMENT_SIZE", str(10 * 1024 * 1024)))  # 10MB default
# CHRONIX-003 FIX: CSV import size and row limits
MAX_CSV_IMPORT_SIZE = int(os.environ.get("CHRONIX_MAX_CSV_SIZE", str(5 * 1024 * 1024)))  # 5MB default
MAX_CSV_ROWS = int(os.environ.get("CHRONIX_MAX_CSV_ROWS", "10000"))
ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}

engine = None
SessionLocal = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine, SessionLocal
    
    try:
        init_security()
    except ValueError as e:
        print(f"[FATAL] {e}")
        raise
    
    # Create attachments directory
    attachments_dir = Path(ATTACHMENTS_PATH)
    attachments_dir.mkdir(parents=True, exist_ok=True)
    print(f"[Storage] Attachments directory: {attachments_dir.absolute()}")
    
    engine = init_db(DATABASE_PATH)
    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(bind=engine)
    
    db = SessionLocal()
    try:
        # Create default admin user if none exists
        if db.query(User).count() == 0:
            default_password = os.environ.get("CHRONIX_ADMIN_PASSWORD", "")
            if not default_password:
                import secrets
                default_password = secrets.token_urlsafe(16)
                print(f"\n{'='*60}")
                print(f"[SETUP] Default admin: admin / {default_password}")
                print(f"        Change this password immediately!")
                print(f"{'='*60}\n")
            
            admin = User(
                username="admin",
                password_hash=hash_password(default_password),
                display_name="Administrator",
                role=DBUserRole.ADMIN,
            )
            db.add(admin)
            db.commit()
        
        # Auto-create default workspace if none exists
        if db.query(Engagement).count() == 0:
            workspace = Engagement(
                name="Workspace",
                description="Operational workspace",
                status=DBEngagementStatus.ACTIVE,
            )
            db.add(workspace)
            db.commit()
            print("[SETUP] Created default workspace")
    finally:
        db.close()
    
    import asyncio
    async def cleanup():
        while True:
            await asyncio.sleep(300)
            session_store.cleanup_expired()
            login_rate_limiter.cleanup()
            write_rate_limiter.cleanup()
    
    task = asyncio.create_task(cleanup())
    yield
    task.cancel()
    engine.dispose()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


app = FastAPI(
    title="Chronix",
    description="Pentesting Workspace",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if os.environ.get("CHRONIX_DEBUG", "").lower() == "true" else None,
    redoc_url=None,
)

origins = get_cors_origins()
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in get_security_headers().items():
        response.headers[k] = v
    return response


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    """
    CHRONIX-001 FIX: Global CSRF enforcement for all state-changing requests.
    Validates X-CSRF-Token header against the session-bound CSRF token.
    """
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
    # Login needs to work without a session; logout is safe to exempt
    EXEMPT_PATHS = {"/api/auth/login", "/api/auth/logout"}
    
    if request.method not in SAFE_METHODS and request.url.path not in EXEMPT_PATHS:
        # Only enforce on /api/ paths (not static files or SPA routes)
        if request.url.path.startswith("/api/"):
            from .security import verify_csrf_token
            sid = request.cookies.get(SecurityConfig.SESSION_COOKIE_NAME)
            token = request.headers.get("X-CSRF-Token", "")
            if not sid or not token or not verify_csrf_token(sid, token):
                return Response("CSRF token required", status_code=403)
    
    return await call_next(request)


FRONTEND_DIR = Path(__file__).parent / "frontend_dist"


class ConnectionManager:
    def __init__(self):
        self.connections: dict[str, list[tuple[WebSocket, str, str]]] = {}
    
    async def connect(self, ws: WebSocket, eng_id: str, user_id: str, sess_id: str):
        # NOTE: WebSocket is already accepted in ws_endpoint before calling this method
        # Do NOT call ws.accept() here - it would cause ASGI protocol violation
        self.connections.setdefault(eng_id, []).append((ws, user_id, sess_id))
    
    def disconnect(self, ws: WebSocket, eng_id: str):
        if eng_id in self.connections:
            self.connections[eng_id] = [(w, u, s) for w, u, s in self.connections[eng_id] if w != ws]
    
    async def broadcast(self, eng_id: str, msg: dict):
        if eng_id not in self.connections:
            return
        dead = []
        for ws, uid, sid in self.connections[eng_id]:
            try:
                sess = session_store.get(sid)
                if sess and sess.has_engagement_access(eng_id):
                    await ws.send_json(msg)
                else:
                    dead.append(ws)
            except:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, eng_id)


manager = ConnectionManager()


def get_user_engagement_ids(db: Session, user_id: str) -> List[str]:
    return [r[0] for r in db.query(user_engagement_access.c.engagement_id).filter(
        user_engagement_access.c.user_id == user_id
    ).all()]


def verify_engagement_access(db: Session, session: SessionData, eng_id: str) -> Engagement:
    eng = db.query(Engagement).filter(Engagement.id == eng_id).first()
    if not eng:
        raise HTTPException(404, "Engagement not found")
    if not session.has_engagement_access(eng_id):
        raise HTTPException(403, "Access denied")
    return eng


def entry_to_response(e: TimelineEntry) -> TimelineEntryResponse:
    name = e.user.display_name if e.user else (e.operator.display_name if e.operator else "Unknown")
    return TimelineEntryResponse(
        id=e.id, engagement_id=e.engagement_id, operator_id=e.user_id or e.operator_id or "",
        operator_name=name, start_time=e.start_time, end_time=e.end_time,
        source_ip=e.source_ip, destination_ip=e.destination_ip, destination_port=e.destination_port,
        destination_system=e.destination_system, pivot_ip=e.pivot_ip, pivot_port=e.pivot_port,
        url=e.url, tool_app=e.tool_app, command=e.command, description=e.description,
        output=e.output, result=e.result,
        system_modification=SystemModification(e.system_modification.value) if e.system_modification else SystemModification.UNKNOWN,
        action_type=ActionType(e.action_type.value) if e.action_type else None,
        comments=e.comments, created_at=e.created_at, updated_at=e.updated_at, is_deleted=e.is_deleted
    )


def notepage_to_response(p: NotePage, db: Session) -> NotePageResponse:
    editor = db.query(User).filter(User.id == p.edited_by).first() if p.edited_by else None
    if not editor:
        editor = db.query(Operator).filter(Operator.id == p.edited_by).first() if p.edited_by else None
    return NotePageResponse(
        id=p.id, engagement_id=p.engagement_id, title=p.title, content=p.content,
        order_index=p.order_index, version=p.version, created_at=p.created_at, updated_at=p.updated_at,
        edited_by=p.edited_by, editor_name=editor.display_name if editor else None
    )


# === Auth ===

@app.post("/api/auth/login", response_model=LoginResponse)
async def login(request: Request, response: Response, creds: LoginRequest, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    if not check_login_rate_limit(ip):
        raise HTTPException(429, "Too many attempts")
    
    user = db.query(User).filter(User.username == creds.username).first()
    if not user or not user.is_active or not verify_password(creds.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(creds.password)
    user.last_login = datetime.utcnow()
    db.commit()
    
    eng_ids = None if user.role == DBUserRole.ADMIN else get_user_engagement_ids(db, user.id)
    sess_id = session_store.create(user.id, user.username, UserRole(user.role.value), ip, request.headers.get("User-Agent", ""), eng_ids)
    set_session_cookie(response, sess_id)
    
    return LoginResponse(user_id=user.id, username=user.username, display_name=user.display_name,
                         role=UserRole(user.role.value), csrf_token=generate_csrf_token(sess_id))


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    sid = request.cookies.get(SecurityConfig.SESSION_COOKIE_NAME)
    if sid:
        session_store.delete(sid)
    clear_session_cookie(response)
    return {"message": "Logged out"}


@app.get("/api/auth/me", response_model=LoginResponse)
async def me(request: Request, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == session.user_id).first()
    sid = request.cookies.get(SecurityConfig.SESSION_COOKIE_NAME)
    return LoginResponse(user_id=session.user_id, username=session.username,
                         display_name=user.display_name if user else session.username,
                         role=session.role, csrf_token=generate_csrf_token(sid) if sid else "")


@app.post("/api/auth/change-password")
async def change_pwd(request: Request, response: Response, data: PasswordChange,
                     session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == session.user_id).first()
    if not user or not verify_password(data.current_password, user.password_hash):
        raise HTTPException(401, "Wrong password")
    user.password_hash = hash_password(data.new_password)
    user.password_changed_at = datetime.utcnow()
    db.commit()
    session_store.delete_all_for_user(user.id)
    clear_session_cookie(response)
    return {"message": "Password changed"}


# === Users (Single-User Model) ===
# Single user account created via `chronix init`.
# User management endpoints are blocked.

@app.post("/api/users", response_model=UserResponse)
async def create_user(data: UserCreate, session: SessionData = Depends(require_permission(Permission.USER_CREATE)), db: Session = Depends(get_db)):
    """User creation is not available. Use `chronix init` to set up the admin account."""
    raise HTTPException(
        status_code=403, 
        detail="Chronix uses a single user account. User management is not available."
    )


@app.get("/api/users", response_model=List[UserResponse])
async def list_users(session: SessionData = Depends(require_permission(Permission.USER_LIST)), db: Session = Depends(get_db)):
    """Returns the single user for compatibility."""
    return [UserResponse(id=u.id, username=u.username, display_name=u.display_name,
                         role=UserRole(u.role.value), is_active=u.is_active,
                         created_at=u.created_at, last_login=u.last_login,
                         engagement_ids=None)
            for u in db.query(User).filter(User.is_active == True).all()]


@app.patch("/api/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: str, data: UserUpdate, session: SessionData = Depends(require_permission(Permission.USER_UPDATE)), db: Session = Depends(get_db)):
    """Only display name updates are allowed."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Not found")
    # Only allow display name changes, not role or status changes
    if data.role is not None or data.is_active is not None:
        raise HTTPException(
            status_code=403,
            detail="Chronix uses a single user account. Role and status changes are not available."
        )
    if data.display_name is not None:
        user.display_name = data.display_name
    db.commit()
    return UserResponse(id=user.id, username=user.username, display_name=user.display_name,
                        role=UserRole(user.role.value), is_active=user.is_active,
                        created_at=user.created_at, last_login=user.last_login,
                        engagement_ids=None)


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str, session: SessionData = Depends(require_permission(Permission.USER_DELETE)), db: Session = Depends(get_db)):
    """User deletion is not available."""
    raise HTTPException(
        status_code=403, 
        detail="Chronix uses a single user account. User management is not available."
    )


# === Operators (Legacy - Disabled) ===
# Legacy operator model kept for database compatibility.

@app.post("/api/operators", response_model=OperatorResponse)
def create_operator(op: OperatorCreate, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    """Operator management is not available. Actions are attributed to the logged-in user."""
    raise HTTPException(
        status_code=403,
        detail="Chronix uses a single user account. Operator management is not available."
    )


@app.get("/api/operators", response_model=List[OperatorResponse])
def list_operators(session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    """Returns empty list for compatibility."""
    return []


@app.get("/api/operators/{oid}", response_model=OperatorResponse)
def get_operator(oid: str, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    o = db.query(Operator).filter(Operator.id == oid).first()
    if not o:
        raise HTTPException(404, "Not found")
    return o


# === Workspace Data ===
# Single implicit workspace. These endpoints use workspace ID from /api/workspace.

@app.get("/api/engagements/{eid}", response_model=EngagementResponse)
def get_engagement(eid: str, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    e = verify_engagement_access(db, session, eid)
    cnt = db.query(TimelineEntry).filter(TimelineEntry.engagement_id == eid, TimelineEntry.is_deleted == False).count()
    return EngagementResponse(id=e.id, name=e.name, client_name=e.client_name, description=e.description,
                              status=EngagementStatus(e.status.value), start_date=e.start_date, end_date=e.end_date,
                              created_at=e.created_at, updated_at=e.updated_at, entry_count=cnt)


# === Timeline ===

@app.get("/api/engagements/{eid}/timeline")
def get_timeline(eid: str, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
                 operator_id: Optional[str] = None, action_type: Optional[ActionType] = None,
                 tool_app: Optional[str] = None, search: Optional[str] = None, include_deleted: bool = False,
                 session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    verify_engagement_access(db, session, eid)
    q = db.query(TimelineEntry).filter(TimelineEntry.engagement_id == eid)
    if not include_deleted:
        q = q.filter(TimelineEntry.is_deleted == False)
    if operator_id:
        q = q.filter(or_(TimelineEntry.user_id == operator_id, TimelineEntry.operator_id == operator_id))
    if action_type:
        q = q.filter(TimelineEntry.action_type == DBActionType(action_type.value))
    if tool_app:
        q = q.filter(TimelineEntry.tool_app.ilike(f"%{tool_app}%"))
    if search:
        t = f"%{search}%"
        q = q.filter(or_(TimelineEntry.description.ilike(t), TimelineEntry.command.ilike(t), TimelineEntry.output.ilike(t)))
    total = q.count()
    entries = q.options(joinedload(TimelineEntry.user), joinedload(TimelineEntry.operator)) \
        .order_by(TimelineEntry.start_time.desc()).offset((page-1)*page_size).limit(page_size).all()
    ops = db.query(distinct(TimelineEntry.user_id)).filter(TimelineEntry.engagement_id == eid, TimelineEntry.is_deleted == False).count()
    tgts = db.query(distinct(TimelineEntry.destination_ip)).filter(TimelineEntry.engagement_id == eid, TimelineEntry.is_deleted == False, TimelineEntry.destination_ip.isnot(None)).count()
    return TimelineListResponse(entries=[entry_to_response(e) for e in entries], total=total, page=page, page_size=page_size, unique_operators=ops, unique_targets=tgts)


@app.post("/api/engagements/{eid}/timeline", response_model=TimelineEntryResponse)
async def create_entry(eid: str, entry: TimelineEntryCreate, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    if Permission.TIMELINE_CREATE not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    if not check_write_rate_limit(session.user_id):
        raise HTTPException(429, "Rate limit")
    e = TimelineEntry(engagement_id=eid, user_id=session.user_id, start_time=entry.start_time or datetime.utcnow(),
                      end_time=entry.end_time, source_ip=entry.source_ip, destination_ip=entry.destination_ip,
                      destination_port=entry.destination_port, destination_system=entry.destination_system,
                      pivot_ip=entry.pivot_ip, pivot_port=entry.pivot_port, url=entry.url, tool_app=entry.tool_app,
                      command=entry.command, description=entry.description, output=entry.output, result=entry.result,
                      system_modification=DBSystemModification(entry.system_modification.value),
                      action_type=DBActionType(entry.action_type.value) if entry.action_type else None, comments=entry.comments)
    db.add(e)
    db.commit()
    r = entry_to_response(e)
    await manager.broadcast(eid, {"type": "timeline_update", "action": "create", "entry": r.model_dump(mode='json')})
    return r


@app.get("/api/engagements/{eid}/timeline/{tid}", response_model=TimelineEntryResponse)
def get_entry(eid: str, tid: str, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    verify_engagement_access(db, session, eid)
    e = db.query(TimelineEntry).options(joinedload(TimelineEntry.user), joinedload(TimelineEntry.operator)) \
        .filter(TimelineEntry.id == tid, TimelineEntry.engagement_id == eid).first()
    if not e:
        raise HTTPException(404, "Not found")
    return entry_to_response(e)


@app.patch("/api/engagements/{eid}/timeline/{tid}", response_model=TimelineEntryResponse)
async def update_entry(eid: str, tid: str, data: TimelineEntryUpdate, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    if Permission.TIMELINE_UPDATE not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    e = db.query(TimelineEntry).filter(TimelineEntry.id == tid, TimelineEntry.engagement_id == eid).first()
    if not e:
        raise HTTPException(404, "Not found")
    for k, v in data.model_dump(exclude_unset=True).items():
        if k == "system_modification" and v:
            setattr(e, k, DBSystemModification(v.value))
        elif k == "action_type" and v:
            setattr(e, k, DBActionType(v.value))
        else:
            setattr(e, k, v)
    db.commit()
    r = entry_to_response(e)
    await manager.broadcast(eid, {"type": "timeline_update", "action": "update", "entry": r.model_dump(mode='json')})
    return r


@app.delete("/api/engagements/{eid}/timeline/{tid}")
async def delete_entry(eid: str, tid: str, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    if Permission.TIMELINE_DELETE not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    e = db.query(TimelineEntry).filter(TimelineEntry.id == tid, TimelineEntry.engagement_id == eid).first()
    if not e:
        raise HTTPException(404, "Not found")
    e.is_deleted = True
    db.commit()
    await manager.broadcast(eid, {"type": "timeline_update", "action": "delete", "entry_id": tid})
    return {"message": "Deleted"}


# === Notes ===

@app.get("/api/engagements/{eid}/note-pages", response_model=NotePageListResponse)
def get_pages(eid: str, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    verify_engagement_access(db, session, eid)
    pages = db.query(NotePage).filter(NotePage.engagement_id == eid).order_by(NotePage.order_index).all()
    return NotePageListResponse(pages=[notepage_to_response(p, db) for p in pages], total=len(pages))


@app.post("/api/engagements/{eid}/note-pages", response_model=NotePageResponse)
async def create_page(eid: str, page: NotePageCreate, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    if Permission.NOTES_CREATE not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    mx = db.query(func.max(NotePage.order_index)).filter(NotePage.engagement_id == eid).scalar() or -1
    p = NotePage(engagement_id=eid, title=sanitize_plain_text(page.title), content=sanitize_markdown(page.content),
                 order_index=mx+1, edited_by=session.user_id)
    db.add(p)
    db.commit()
    r = notepage_to_response(p, db)
    await manager.broadcast(eid, {"type": "notepage_update", "action": "create", "page": r.model_dump(mode='json')})
    return r


@app.get("/api/engagements/{eid}/note-pages/{pid}", response_model=NotePageResponse)
def get_page(eid: str, pid: str, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    verify_engagement_access(db, session, eid)
    p = db.query(NotePage).filter(NotePage.id == pid, NotePage.engagement_id == eid).first()
    if not p:
        raise HTTPException(404, "Not found")
    return notepage_to_response(p, db)


@app.patch("/api/engagements/{eid}/note-pages/{pid}", response_model=NotePageResponse)
async def update_page(eid: str, pid: str, data: NotePageUpdate, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    if Permission.NOTES_UPDATE not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    p = db.query(NotePage).filter(NotePage.id == pid, NotePage.engagement_id == eid).first()
    if not p:
        raise HTTPException(404, "Not found")
    if data.title is not None:
        p.title = sanitize_plain_text(data.title)
    if data.content is not None:
        p.content = sanitize_markdown(data.content)
    if data.order_index is not None:
        p.order_index = data.order_index
    p.edited_by = session.user_id
    p.version += 1
    db.commit()
    r = notepage_to_response(p, db)
    await manager.broadcast(eid, {"type": "notepage_update", "action": "update", "page": r.model_dump(mode='json')})
    return r


@app.delete("/api/engagements/{eid}/note-pages/{pid}")
async def delete_page(eid: str, pid: str, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    if Permission.NOTES_DELETE not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    p = db.query(NotePage).filter(NotePage.id == pid, NotePage.engagement_id == eid).first()
    if not p:
        raise HTTPException(404, "Not found")
    db.delete(p)
    db.commit()
    await manager.broadcast(eid, {"type": "notepage_update", "action": "delete", "page_id": pid})
    return {"message": "Deleted"}


@app.post("/api/engagements/{eid}/note-pages/reorder")
async def reorder_pages(eid: str, data: NotePageReorderRequest, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    """Reorder note pages by updating their order_index values."""
    if Permission.NOTES_UPDATE not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    
    for item in data.page_orders:
        # CHRONIX-009 FIX: item is now a typed PageOrderItem, not raw dict
        p = db.query(NotePage).filter(NotePage.id == item.id, NotePage.engagement_id == eid).first()
        if p:
            p.order_index = item.order_index
    db.commit()
    await manager.broadcast(eid, {"type": "notepage_update", "action": "reorder"})
    return {"message": "Reordered"}


# === Export ===

def sanitize_csv_field(field: str) -> str:
    """
    Sanitize field for CSV export to prevent formula injection.
    
    Prepends single quote to fields starting with =, +, -, @, tab, or carriage return.
    This prevents spreadsheet applications from interpreting the field as a formula.
    
    References:
    - OWASP: https://owasp.org/www-community/attacks/CSV_Injection
    - CWE-1236: Improper Neutralization of Formula Elements in a CSV File
    """
    if not field:
        return field
    if field[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + field
    return field


@app.get("/api/engagements/{eid}/export")
async def export(eid: str, include_deleted: bool = False, session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    if Permission.EXPORT_DATA not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    q = db.query(TimelineEntry).filter(TimelineEntry.engagement_id == eid)
    if not include_deleted:
        q = q.filter(TimelineEntry.is_deleted == False)
    entries = q.options(joinedload(TimelineEntry.user), joinedload(TimelineEntry.operator)).order_by(TimelineEntry.start_time).all()
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=CSV_COLUMNS)
    w.writeheader()
    for e in entries:
        w.writerow({
            "start_time": format_datetime_for_export(e.start_time), "end_time": format_datetime_for_export(e.end_time),
            "operator_name": sanitize_csv_field(e.user.display_name if e.user else (e.operator.display_name if e.operator else "Unknown")),
            "source_ip": sanitize_csv_field(e.source_ip or ""), "destination_ip": sanitize_csv_field(e.destination_ip or ""),
            "destination_port": sanitize_csv_field(e.destination_port or ""), "destination_system": sanitize_csv_field(e.destination_system or ""),
            "pivot_ip": sanitize_csv_field(e.pivot_ip or ""), "pivot_port": sanitize_csv_field(e.pivot_port or ""), "url": sanitize_csv_field(e.url or ""),
            "tool_app": sanitize_csv_field(e.tool_app or ""), "command": sanitize_csv_field(e.command or ""), "description": sanitize_csv_field(e.description or ""),
            "output": sanitize_csv_field(e.output or ""), "result": sanitize_csv_field(e.result or ""),
            "system_modification": sanitize_csv_field(e.system_modification.value if e.system_modification else ""), "comments": sanitize_csv_field(e.comments or ""),
        })
    eng = db.query(Engagement).filter(Engagement.id == eid).first()
    # CHRONIX-002 FIX: Sanitize engagement name to prevent header injection
    safe_name = sanitize_content_disposition(eng.name)
    fn = f"chronix_{safe_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{fn}"'})


def parse_datetime_for_import(value: str) -> Optional[datetime]:
    """Parse datetime from CSV import format (YYYYMMDD_HHMMSS)."""
    if not value or not value.strip():
        return None
    value = value.strip()
    # Try the export format first: YYYYMMDD_HHMMSS
    try:
        return datetime.strptime(value, "%Y%m%d_%H%M%S")
    except ValueError:
        pass
    # Try ISO format as fallback
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        pass
    return None


@app.post("/api/engagements/{eid}/import", response_model=CSVImportResult)
async def import_csv(eid: str, file: UploadFile = File(...), session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    """Import timeline entries from a CSV file."""
    if Permission.TIMELINE_CREATE not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    
    # Read and decode file
    try:
        # CHRONIX-003 FIX: Enforce file size limit before reading entire file
        content = await file.read(MAX_CSV_IMPORT_SIZE + 1)
        if len(content) > MAX_CSV_IMPORT_SIZE:
            return CSVImportResult(success=False, imported_count=0, error_count=1,
                                  errors=[f"CSV file too large (max {MAX_CSV_IMPORT_SIZE} bytes)"])
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        return CSVImportResult(success=False, imported_count=0, error_count=1, errors=["File must be UTF-8 encoded"])
    
    reader = csv.DictReader(io.StringIO(text))
    imported_count = 0
    error_count = 0
    errors = []
    
    for row_num, row in enumerate(reader, start=2):  # Row 2 is first data row after header
        # CHRONIX-003 FIX: Enforce row count limit
        if row_num - 1 > MAX_CSV_ROWS:
            errors.append(f"Row limit ({MAX_CSV_ROWS}) exceeded, import truncated")
            break
        try:
            # Parse start_time (required for a valid entry)
            start_time = parse_datetime_for_import(row.get("start_time", ""))
            if not start_time:
                start_time = datetime.utcnow()
            
            # Map system_modification string to enum
            sys_mod_str = row.get("system_modification", "").strip()
            sys_mod = DBSystemModification.UNKNOWN
            for sm in DBSystemModification:
                if sm.value.lower() == sys_mod_str.lower():
                    sys_mod = sm
                    break
            
            entry = TimelineEntry(
                engagement_id=eid,
                user_id=session.user_id,
                start_time=start_time,
                end_time=parse_datetime_for_import(row.get("end_time", "")),
                source_ip=sanitize_plain_text(row.get("source_ip", ""))[:45] or None,
                destination_ip=sanitize_plain_text(row.get("destination_ip", ""))[:45] or None,
                destination_port=sanitize_plain_text(row.get("destination_port", ""))[:16] or None,
                destination_system=sanitize_plain_text(row.get("destination_system", ""))[:256] or None,
                pivot_ip=sanitize_plain_text(row.get("pivot_ip", ""))[:45] or None,
                pivot_port=sanitize_plain_text(row.get("pivot_port", ""))[:32] or None,
                url=sanitize_plain_text(row.get("url", "")) or None,
                tool_app=sanitize_plain_text(row.get("tool_app", ""))[:128] or None,
                command=sanitize_plain_text(row.get("command", "")) or None,
                description=sanitize_plain_text(row.get("description", "")) or None,
                output=sanitize_plain_text(row.get("output", "")) or None,
                result=sanitize_plain_text(row.get("result", "")) or None,
                system_modification=sys_mod,
                comments=sanitize_plain_text(row.get("comments", "")) or None,
            )
            db.add(entry)
            imported_count += 1
            # CHRONIX-003 FIX: Batch commits to avoid long DB locks
            if imported_count % 500 == 0:
                db.commit()
        except Exception as e:
            error_count += 1
            errors.append(f"Row {row_num}: {str(e)}")
            if len(errors) >= 10:
                errors.append("... (additional errors truncated)")
                break
    
    if imported_count > 0:
        db.commit()
        # Broadcast update for real-time sync
        await manager.broadcast(eid, {"type": "timeline_update", "action": "import", "count": imported_count})
    
    return CSVImportResult(
        success=error_count == 0,
        imported_count=imported_count,
        error_count=error_count,
        errors=errors
    )


# === Note Attachments ===

def slugify(text: str, max_length: int = 50) -> str:
    """
    Convert text to a safe filename slug.
    - Lowercase
    - Replace spaces and special chars with hyphens
    - Remove consecutive hyphens
    - Truncate to max_length
    """
    text = text.lower().strip()
    # Replace spaces and common separators with hyphens
    text = re.sub(r'[\s_]+', '-', text)
    # Remove any non-alphanumeric characters (except hyphens)
    text = re.sub(r'[^a-z0-9\-]', '', text)
    # Remove consecutive hyphens
    text = re.sub(r'-+', '-', text)
    # Remove leading/trailing hyphens
    text = text.strip('-')
    # Truncate
    if len(text) > max_length:
        text = text[:max_length].rstrip('-')
    return text or 'untitled'


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal and other attacks.
    """
    # Remove path components
    filename = os.path.basename(filename)
    # Remove null bytes and other dangerous characters
    filename = re.sub(r'[\x00-\x1f\x7f<>:"/\\|?*]', '', filename)
    # Limit length
    name, ext = os.path.splitext(filename)
    if len(name) > 100:
        name = name[:100]
    if len(ext) > 10:
        ext = ext[:10]
    return f"{name}{ext}" if name else f"file{ext}"


def generate_stored_filename(note_page_id: str, original_filename: str) -> str:
    """
    Generate a unique stored filename.
    Format: {note_id_prefix}_{timestamp}_{uuid}.{ext}
    """
    ext = os.path.splitext(original_filename)[1].lower() or '.png'
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    unique_id = str(uuid.uuid4())[:8]
    return f"{note_page_id[:8]}_{timestamp}_{unique_id}{ext}"


def attachment_to_response(att: NoteAttachment) -> NoteAttachmentResponse:
    """Convert NoteAttachment model to response schema."""
    return NoteAttachmentResponse(
        id=att.id,
        note_page_id=att.note_page_id,
        engagement_id=att.engagement_id,
        filename=att.filename,
        # CHRONIX-010 FIX: stored_filename removed from response
        mime_type=att.mime_type,
        file_size=att.file_size,
        alt_text=att.alt_text or "",
        created_at=att.created_at,
        uploaded_by=att.uploaded_by,
        # Use filename-based URL for backward compatibility with existing
        # markdown content. The /api/attachments/{filename} endpoint does
        # DB-first lookup so the filename never touches the filesystem raw.
        url=f"/api/attachments/{att.stored_filename}"
    )


@app.post("/api/engagements/{eid}/note-pages/{pid}/attachments", response_model=NoteAttachmentResponse)
async def upload_attachment(
    eid: str, 
    pid: str, 
    file: UploadFile = File(...),
    alt_text: str = "",
    session: SessionData = Depends(get_current_session), 
    db: Session = Depends(get_db)
):
    """
    Upload an image attachment for a note page.
    
    Supports PNG, JPEG, GIF, WebP images up to 10MB (configurable).
    Returns the attachment info including the URL to embed in markdown.
    """
    if Permission.NOTES_UPDATE not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    
    # Verify note page exists
    page = db.query(NotePage).filter(NotePage.id == pid, NotePage.engagement_id == eid).first()
    if not page:
        raise HTTPException(404, "Note page not found")
    
    # Validate MIME type
    content_type = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
    if content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            400, 
            f"Invalid file type: {content_type}. Allowed: {', '.join(ALLOWED_MIME_TYPES)}"
        )
    
    # Read file content
    content = await file.read()
    file_size = len(content)
    
    # Validate file size
    if file_size > MAX_ATTACHMENT_SIZE:
        raise HTTPException(
            400, 
            f"File too large: {file_size} bytes. Maximum: {MAX_ATTACHMENT_SIZE} bytes"
        )
    
    # Validate file content (magic bytes check)
    magic_bytes = {
        b'\x89PNG': 'image/png',
        b'\xff\xd8\xff': 'image/jpeg',
        b'GIF87a': 'image/gif',
        b'GIF89a': 'image/gif',
        b'RIFF': 'image/webp',  # WebP starts with RIFF
    }
    detected_type = None
    for magic, mime in magic_bytes.items():
        if content.startswith(magic):
            detected_type = mime
            break
    
    # Special check for WebP (RIFF + WEBP)
    if content[:4] == b'RIFF' and content[8:12] == b'WEBP':
        detected_type = 'image/webp'
    
    if detected_type is None or detected_type != content_type:
        raise HTTPException(400, "File content does not match declared type")
    
    # Generate safe filenames
    original_filename = sanitize_filename(file.filename or "image.png")
    stored_filename = generate_stored_filename(pid, original_filename)
    
    # Save file to disk — use secure_resolve to validate even the generated path
    attachments_dir = Path(ATTACHMENTS_PATH)
    file_path = secure_resolve(
        attachments_dir,
        stored_filename,
        must_exist=False,
        request_context={
            "user_id": session.user_id,
            "ip": "upload",
            "endpoint": "upload_attachment",
        },
    )
    
    try:
        # O_CREAT|O_EXCL ensures atomic create — fails if file already exists
        fd = os.open(str(file_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
    except FileExistsError:
        raise HTTPException(500, "File collision — retry upload")
    except IOError as e:
        raise HTTPException(500, f"Failed to save file: {e}")
    
    # Create database record
    attachment = NoteAttachment(
        note_page_id=pid,
        engagement_id=eid,
        filename=original_filename,
        stored_filename=stored_filename,
        mime_type=content_type,
        file_size=file_size,
        alt_text=sanitize_plain_text(alt_text) if alt_text else "",
        uploaded_by=session.user_id
    )
    db.add(attachment)
    db.commit()
    
    return attachment_to_response(attachment)


@app.get("/api/engagements/{eid}/note-pages/{pid}/attachments", response_model=NoteAttachmentListResponse)
def list_attachments(
    eid: str, 
    pid: str,
    session: SessionData = Depends(get_current_session), 
    db: Session = Depends(get_db)
):
    """List all attachments for a note page."""
    verify_engagement_access(db, session, eid)
    
    attachments = db.query(NoteAttachment).filter(
        NoteAttachment.note_page_id == pid,
        NoteAttachment.engagement_id == eid
    ).order_by(NoteAttachment.created_at).all()
    
    return NoteAttachmentListResponse(
        attachments=[attachment_to_response(a) for a in attachments],
        total=len(attachments)
    )


@app.delete("/api/engagements/{eid}/note-pages/{pid}/attachments/{aid}")
async def delete_attachment(
    eid: str, 
    pid: str, 
    aid: str,
    session: SessionData = Depends(get_current_session), 
    db: Session = Depends(get_db)
):
    """Delete an attachment."""
    if Permission.NOTES_DELETE not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    
    attachment = db.query(NoteAttachment).filter(
        NoteAttachment.id == aid,
        NoteAttachment.note_page_id == pid,
        NoteAttachment.engagement_id == eid
    ).first()
    
    if not attachment:
        raise HTTPException(404, "Attachment not found")
    
    # Delete file from disk (with secure path resolution)
    try:
        file_path = secure_resolve(
            Path(ATTACHMENTS_PATH),
            attachment.stored_filename,
            must_exist=False,  # File may already be gone
        )
        if file_path.exists():
            file_path.unlink()
    except (HTTPException, IOError):
        pass  # File already gone or path invalid, continue with DB cleanup
    
    # Delete database record
    db.delete(attachment)
    db.commit()
    
    return {"message": "Deleted"}


@app.get("/api/attachments/by-id/{attachment_id}")
async def serve_attachment_by_id(
    attachment_id: str,
    request: Request,
    session: SessionData = Depends(get_current_session),
    db: Session = Depends(get_db),
):
    """
    Serve an attachment file by database ID (primary endpoint).

    Security layers:
      1. Database lookup by opaque UUID — user never controls filesystem path
      2. Engagement access verified
      3. Filename validated + path resolved (L1-L6) even for DB-sourced values
      4. O_NOFOLLOW fd-based open eliminates TOCTOU race (L7)
      5. fstat confirms regular file after open
      6. Content-Disposition header sanitized (L8)
    """
    # Validate attachment_id format (UUID)
    try:
        uuid.UUID(attachment_id, version=4)
    except ValueError:
        raise HTTPException(400, "Invalid attachment ID")

    attachment = db.query(NoteAttachment).filter(
        NoteAttachment.id == attachment_id
    ).first()
    if not attachment:
        raise HTTPException(404, "Attachment not found")

    if not session.has_engagement_access(attachment.engagement_id):
        raise HTTPException(403, "Access denied")

    request_ctx = {
        "user_id": session.user_id,
        "ip": get_client_ip(request),
        "endpoint": "serve_attachment_by_id",
    }

    attachments_dir = Path(ATTACHMENTS_PATH)

    # L1-L7: secure_open validates filename, containment, symlinks,
    # then opens with O_NOFOLLOW and verifies via fstat — atomic.
    file_obj = secure_open(
        attachments_dir,
        attachment.stored_filename,
        request_context=request_ctx,
    )

    safe_display = sanitize_content_disposition(attachment.filename)

    # Stream from the open fd — no path-based FileResponse, no TOCTOU window.
    return StreamingResponse(
        file_obj,
        media_type=attachment.mime_type,
        headers={
            "Content-Disposition": f'inline; filename="{safe_display}"',
            "Cache-Control": "private, max-age=86400",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/attachments/{filename}")
async def serve_attachment(
    filename: str,
    request: Request,
    session: SessionData = Depends(get_current_session),
    db: Session = Depends(get_db),
):
    """
    Serve an attachment file by stored filename (backward-compatible endpoint).

    Kept for backward compatibility with existing markdown content that
    references attachments by filename. New code should use /api/attachments/by-id/.

    Same security stack as serve_attachment_by_id: DB lookup first, then
    fd-based serving via secure_open.
    """
    request_ctx = {
        "user_id": session.user_id,
        "ip": get_client_ip(request),
        "endpoint": "serve_attachment",
    }

    # DB lookup first — never touch the filesystem with raw user input.
    # The filename from the URL is only used as a DB query filter, not
    # as a filesystem path component.
    attachment = db.query(NoteAttachment).filter(
        NoteAttachment.stored_filename == filename
    ).first()
    if not attachment:
        raise HTTPException(404, "Attachment not found")

    if not session.has_engagement_access(attachment.engagement_id):
        raise HTTPException(403, "Access denied")

    attachments_dir = Path(ATTACHMENTS_PATH)

    # L1-L7: Use the DB-sourced stored_filename (not the URL parameter)
    # through secure_open for full validation + TOCTOU protection.
    file_obj = secure_open(
        attachments_dir,
        attachment.stored_filename,
        request_context=request_ctx,
    )

    safe_display = sanitize_content_disposition(attachment.filename)

    return StreamingResponse(
        file_obj,
        media_type=attachment.mime_type,
        headers={
            "Content-Disposition": f'inline; filename="{safe_display}"',
            "Cache-Control": "private, max-age=86400",
            "X-Content-Type-Options": "nosniff",
        },
    )


# === Markdown Export ===

def generate_yaml_frontmatter(page: NotePage, engagement: Engagement) -> str:
    """Generate YAML frontmatter for exported markdown."""
    frontmatter = [
        "---",
        "title: \"{}\"".format(page.title.replace('"', '\\"')),
        f"note_id: \"{page.id}\"",
        f"engagement_id: \"{engagement.id}\"",
        f"created_at: \"{page.created_at.isoformat()}\"",
        f"updated_at: \"{page.updated_at.isoformat()}\"",
        "---",
        ""
    ]
    return "\n".join(frontmatter)


def generate_export_filename(title: str, note_id: str) -> str:
    """
    Generate a safe filename for export.
    Format: {slugified-title}__note_{note_id_prefix}.md
    """
    slug = slugify(title)
    return f"{slug}__note_{note_id[:8]}.md"


def rewrite_attachment_paths(content: str, attachments: List[NoteAttachment]) -> str:
    """
    Rewrite attachment URLs in markdown content to use relative paths.
    
    Converts: ![alt](/api/attachments/filename.png)
    To:       ![alt](./attachments/filename.png)
    """
    for att in attachments:
        # Match both old and new URL formats
        patterns = [
            f"/api/attachments/{att.stored_filename}",
            f"./attachments/{att.stored_filename}",
        ]
        replacement = f"./attachments/{att.stored_filename}"
        for pattern in patterns:
            content = content.replace(pattern, replacement)
    return content


@app.get("/api/engagements/{eid}/note-pages/{pid}/export")
async def export_note_markdown(
    eid: str, 
    pid: str,
    include_frontmatter: bool = True,
    session: SessionData = Depends(get_current_session), 
    db: Session = Depends(get_db)
):
    """
    Export a single note page as Markdown (.md) file.
    
    Includes YAML frontmatter with metadata and rewrites attachment URLs
    to use relative paths (./attachments/).
    """
    if Permission.EXPORT_DATA not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    
    page = db.query(NotePage).filter(NotePage.id == pid, NotePage.engagement_id == eid).first()
    if not page:
        raise HTTPException(404, "Note page not found")
    
    engagement = db.query(Engagement).filter(Engagement.id == eid).first()
    
    # Get attachments for this page
    attachments = db.query(NoteAttachment).filter(NoteAttachment.note_page_id == pid).all()
    
    # Build markdown content
    parts = []
    if include_frontmatter:
        parts.append(generate_yaml_frontmatter(page, engagement))
    
    content = page.content or ""
    content = rewrite_attachment_paths(content, attachments)
    parts.append(content)
    
    markdown_content = "\n".join(parts)
    
    # Generate filename
    filename = generate_export_filename(page.title, page.id)
    
    return StreamingResponse(
        iter([markdown_content]),
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        }
    )


@app.get("/api/engagements/{eid}/notes/export")
async def export_all_notes_zip(
    eid: str,
    include_frontmatter: bool = True,
    include_attachments: bool = True,
    session: SessionData = Depends(get_current_session), 
    db: Session = Depends(get_db)
):
    """
    Export all note pages as a ZIP archive containing:
    - Individual .md files for each note
    - attachments/ folder with all images
    
    Structure:
    chronix_notes_YYYYMMDD_HHMMSS.zip
    ├── note-title__note_abc123.md
    ├── another-note__note_def456.md
    └── attachments/
        ├── abc12345_20240101_123456_a1b2c3d4.png
        └── ...
    """
    if Permission.EXPORT_DATA not in ROLE_PERMISSIONS.get(session.role, set()):
        raise HTTPException(403, "Denied")
    verify_engagement_access(db, session, eid)
    
    engagement = db.query(Engagement).filter(Engagement.id == eid).first()
    if not engagement:
        raise HTTPException(404, "Engagement not found")
    
    pages = db.query(NotePage).filter(NotePage.engagement_id == eid).order_by(NotePage.order_index).all()
    
    # Create zip in memory
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Track which attachments to include
        all_attachments = []
        
        for page in pages:
            # Get attachments for this page
            attachments = db.query(NoteAttachment).filter(NoteAttachment.note_page_id == page.id).all()
            all_attachments.extend(attachments)
            
            # Build markdown content
            parts = []
            if include_frontmatter:
                parts.append(generate_yaml_frontmatter(page, engagement))
            
            content = page.content or ""
            content = rewrite_attachment_paths(content, attachments)
            parts.append(content)
            
            markdown_content = "\n".join(parts)
            
            # Generate filename and add to zip
            filename = generate_export_filename(page.title, page.id)
            zf.writestr(filename, markdown_content.encode('utf-8'))
        
        # Add attachments folder
        if include_attachments and all_attachments:
            attachments_dir = Path(ATTACHMENTS_PATH)
            for att in all_attachments:
                try:
                    # Secure path resolution — validates containment even for DB-sourced filenames
                    file_path = secure_resolve(
                        attachments_dir,
                        att.stored_filename,
                        must_exist=True,
                    )
                    arcname = f"attachments/{att.stored_filename}"
                    zf.write(file_path, arcname)
                except HTTPException:
                    # Skip attachments that fail security validation (log is handled by secure_resolve)
                    continue
    
    # Prepare response
    zip_buffer.seek(0)
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    # CHRONIX-002 FIX: Use sanitize_content_disposition for header safety
    safe_name = sanitize_content_disposition(engagement.name)
    zip_filename = f"chronix_notes_{safe_name}_{timestamp}.zip"
    
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{zip_filename}"',
        }
    )


# === WebSocket ===

@app.websocket("/ws/{eid}")
async def ws_endpoint(ws: WebSocket, eid: str):
    # CHRONIX-012 FIX: Validate session cookie BEFORE accepting the WebSocket
    # This prevents resource exhaustion from unauthenticated connection floods
    session_id = ws.cookies.get(SecurityConfig.SESSION_COOKIE_NAME)
    if not session_id:
        await ws.close(4001, "No session")
        return
    sess = session_store.get(session_id)
    if not sess:
        await ws.close(4001, "Invalid session")
        return
    if not sess.has_engagement_access(eid):
        await ws.close(4003, "Access denied")
        return
    
    # Only accept after authentication passes
    await ws.accept()
    await manager.connect(ws, eid, sess.user_id, session_id)
    db = SessionLocal()
    try:
        pres = db.query(OperatorPresence).filter(OperatorPresence.engagement_id == eid, OperatorPresence.operator_id == sess.user_id).first()
        if pres:
            pres.last_heartbeat = datetime.utcnow()
        else:
            db.add(OperatorPresence(engagement_id=eid, operator_id=sess.user_id, current_view="timeline"))
        db.commit()
    finally:
        db.close()
    try:
        while True:
            # CHRONIX-008 FIX: Handle malformed JSON gracefully
            try:
                data = await ws.receive_json()
            except (ValueError, KeyError):
                # Malformed JSON — ignore frame, keep connection open
                continue
            except Exception:
                # Unexpected parse error — close cleanly
                break
            if not session_store.get(session_id):
                await ws.close(4001, "Expired")
                break
            if data.get("type") == "heartbeat":
                db = SessionLocal()
                try:
                    pres = db.query(OperatorPresence).filter(OperatorPresence.engagement_id == eid, OperatorPresence.operator_id == sess.user_id).first()
                    if pres:
                        pres.last_heartbeat = datetime.utcnow()
                        # CHRONIX-004 FIX: Allowlist the view field
                        VALID_VIEWS = {"timeline", "notes", "export"}
                        view_val = data.get("view", "timeline")
                        if not isinstance(view_val, str) or view_val not in VALID_VIEWS:
                            view_val = "timeline"
                        pres.current_view = view_val
                        db.commit()
                finally:
                    db.close()
    except WebSocketDisconnect:
        pass
    finally:
        # CHRONIX-008 FIX: Always clean up presence in finally block
        manager.disconnect(ws, eid)
        db = SessionLocal()
        try:
            db.query(OperatorPresence).filter(OperatorPresence.engagement_id == eid, OperatorPresence.operator_id == sess.user_id).delete()
            db.commit()
        finally:
            db.close()


# === Health & Workspace ===

@app.get("/api/health")
def health():
    return {"status": "healthy"}


@app.get("/license")
def license_info():
    """Return licensing information for AGPLv3 compliance."""
    return {
        "name": "Chronix",
        "license": "AGPL-3.0-only",
        "license_url": "https://www.gnu.org/licenses/agpl-3.0.html",
        "source_url": "https://github.com/icecubesandwich/chronix"
    }


@app.get("/api/workspace")
def get_workspace(session: SessionData = Depends(get_current_session), db: Session = Depends(get_db)):
    """
    Get the default workspace.
    Returns the single workspace for direct navigation after login.
    """
    workspace = db.query(Engagement).first()
    if not workspace:
        raise HTTPException(500, "Workspace not initialized")
    
    entry_count = db.query(TimelineEntry).filter(
        TimelineEntry.engagement_id == workspace.id,
        TimelineEntry.is_deleted == False
    ).count()
    
    return {
        "id": workspace.id,
        "entry_count": entry_count,
    }


# === Frontend ===

if FRONTEND_DIR.exists() and (FRONTEND_DIR / "index.html").exists():
    # Pre-resolve at startup — immutable after this point
    _RESOLVED_FRONTEND = FRONTEND_DIR.resolve()
    _INDEX_HTML = FRONTEND_DIR / "index.html"

    # Allowlisted static asset prefixes that may contain sub-paths.
    # Everything else gets index.html (SPA client-side routing).
    _SPA_STATIC_PREFIXES = ("assets/",)

    if (FRONTEND_DIR / "assets").exists():
        app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")
    
    @app.get("/", response_class=HTMLResponse)
    async def index():
        return FileResponse(_INDEX_HTML)
    
    @app.get("/{path:path}")
    async def spa(path: str):
        # PHASE 7: Strict allowlist — only serve files under known prefixes.
        # For any path that doesn't match a static prefix, return index.html.
        # This eliminates filesystem timing oracles entirely: non-allowlisted
        # paths always return the same response regardless of what exists on disk.
        #
        # Static assets under /assets/ are handled by StaticFiles mount above,
        # so this catch-all only handles SPA client-side routes.
        
        # Fast path: if this isn't a known static prefix, it's a SPA route.
        if not any(path.startswith(p) for p in _SPA_STATIC_PREFIXES):
            return FileResponse(_INDEX_HTML)
        
        # For allowlisted prefixes: resolve canonically + verify containment.
        # This handles files not caught by the StaticFiles mount (edge cases).
        resolved = (FRONTEND_DIR / path).resolve()
        if (
            resolved.is_relative_to(_RESOLVED_FRONTEND)
            and resolved.exists()
            and resolved.is_file()
            and not resolved.is_symlink()
            # L6: reject special files
            and stat.S_ISREG(os.lstat(resolved).st_mode)
        ):
            return FileResponse(resolved)
        
        return FileResponse(_INDEX_HTML)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
