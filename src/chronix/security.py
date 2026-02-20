# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Tyrrell Brewster

"""
Chronix Security Module

Implements:
- Password hashing (Argon2)
- Session management (server-side sessions with secure cookies)
- Role-based access control (Admin, Operator, ReadOnly)
- Engagement-scoped permissions
- Rate limiting (in-memory, no Redis required)
- CSRF protection
- Input sanitization

Design decisions:
- Sessions over JWTs: Server-side sessions allow immediate invalidation on logout,
  role changes, or security incidents. JWTs require token blacklisting which adds
  complexity. For a self-hosted app with <100 concurrent users, session storage
  overhead is negligible.
- Argon2 over bcrypt: Winner of the Password Hashing Competition, resistant to
  GPU/ASIC attacks, memory-hard by design.
- In-memory rate limiting: Simple, no external dependencies. Acceptable for
  single-instance deployments. For multi-instance, use Redis or database.
"""

import os
import re
import secrets
import hashlib
import time
import html
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Set, Tuple
from enum import Enum
from collections import defaultdict
import threading

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from pydantic import BaseModel, Field, field_validator
from fastapi import Request, Response, HTTPException, Depends, status
from fastapi.security import APIKeyCookie
from sqlalchemy.orm import Session
import bleach


# =============================================================================
# Configuration (loaded from environment)
# =============================================================================

class SecurityConfig:
    """Security configuration loaded from environment variables"""
    
    # Session settings
    SESSION_SECRET: str = os.environ.get("CHRONIX_SESSION_SECRET", "")
    SESSION_EXPIRE_HOURS: int = int(os.environ.get("CHRONIX_SESSION_EXPIRE_HOURS", "24"))
    SESSION_COOKIE_NAME: str = "chronix_session"
    
    # CORS settings
    CORS_ALLOWED_ORIGINS: List[str] = []
    
    # Rate limiting
    RATE_LIMIT_LOGIN_ATTEMPTS: int = int(os.environ.get("CHRONIX_RATE_LIMIT_LOGIN", "5"))
    RATE_LIMIT_LOGIN_WINDOW: int = int(os.environ.get("CHRONIX_RATE_LIMIT_LOGIN_WINDOW", "300"))  # 5 min
    RATE_LIMIT_WRITE_REQUESTS: int = int(os.environ.get("CHRONIX_RATE_LIMIT_WRITE", "100"))
    RATE_LIMIT_WRITE_WINDOW: int = int(os.environ.get("CHRONIX_RATE_LIMIT_WRITE_WINDOW", "60"))  # 1 min
    
    # Environment mode
    DEBUG_MODE: bool = os.environ.get("CHRONIX_DEBUG", "false").lower() == "true"
    
    # TLS/Proxy settings
    BEHIND_PROXY: bool = os.environ.get("CHRONIX_BEHIND_PROXY", "false").lower() == "true"
    
    @classmethod
    def load(cls):
        """Load and validate configuration from environment variables.
        
        This must be called at runtime after config file is loaded into os.environ.
        Class attributes are evaluated at import time, so we re-read them here.
        
        Note: Initialization check (missing session secret) is performed in the CLI
        before the ASGI app starts. This method assumes the app is properly initialized.
        """
        # Re-read all config from environment (config file has been loaded by CLI)
        cls.SESSION_SECRET = os.environ.get("CHRONIX_SESSION_SECRET", "")
        cls.SESSION_EXPIRE_HOURS = int(os.environ.get("CHRONIX_SESSION_EXPIRE_HOURS", "24"))
        cls.RATE_LIMIT_LOGIN_ATTEMPTS = int(os.environ.get("CHRONIX_RATE_LIMIT_LOGIN", "5"))
        cls.RATE_LIMIT_LOGIN_WINDOW = int(os.environ.get("CHRONIX_RATE_LIMIT_LOGIN_WINDOW", "300"))
        cls.RATE_LIMIT_WRITE_REQUESTS = int(os.environ.get("CHRONIX_RATE_LIMIT_WRITE", "100"))
        cls.RATE_LIMIT_WRITE_WINDOW = int(os.environ.get("CHRONIX_RATE_LIMIT_WRITE_WINDOW", "60"))
        cls.DEBUG_MODE = os.environ.get("CHRONIX_DEBUG", "false").lower() == "true"
        cls.BEHIND_PROXY = os.environ.get("CHRONIX_BEHIND_PROXY", "false").lower() == "true"
        
        # Parse CORS origins
        cors_env = os.environ.get("CHRONIX_CORS_ORIGINS", "")
        if cors_env:
            cls.CORS_ALLOWED_ORIGINS = [o.strip() for o in cors_env.split(",") if o.strip()]
        
        # Use random secret in debug mode if not set
        if not cls.SESSION_SECRET:
            cls.SESSION_SECRET = secrets.token_hex(32)
            print("[SECURITY WARNING] Debug mode: using temporary session secret.")
            print("                   Sessions will not persist across restarts.")
        
        return cls


# =============================================================================
# Enums and Models
# =============================================================================

class UserRole(str, Enum):
    """User roles with hierarchical permissions"""
    ADMIN = "admin"         # Full access: manage users, all engagements
    OPERATOR = "operator"   # Read/write on assigned engagements
    READONLY = "readonly"   # Read-only on assigned engagements


class Permission(str, Enum):
    """Granular permissions"""
    # User management
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_LIST = "user:list"
    
    # Engagement management
    ENGAGEMENT_CREATE = "engagement:create"
    ENGAGEMENT_UPDATE = "engagement:update"
    ENGAGEMENT_DELETE = "engagement:delete"
    ENGAGEMENT_READ = "engagement:read"
    
    # Timeline
    TIMELINE_CREATE = "timeline:create"
    TIMELINE_UPDATE = "timeline:update"
    TIMELINE_DELETE = "timeline:delete"
    TIMELINE_READ = "timeline:read"
    
    # Notes
    NOTES_CREATE = "notes:create"
    NOTES_UPDATE = "notes:update"
    NOTES_DELETE = "notes:delete"
    NOTES_READ = "notes:read"
    
    # Export
    EXPORT_DATA = "export:data"


# Role -> Permissions mapping
ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: set(Permission),  # All permissions
    UserRole.OPERATOR: {
        Permission.ENGAGEMENT_READ,
        Permission.ENGAGEMENT_UPDATE,
        Permission.TIMELINE_CREATE,
        Permission.TIMELINE_UPDATE,
        Permission.TIMELINE_DELETE,
        Permission.TIMELINE_READ,
        Permission.NOTES_CREATE,
        Permission.NOTES_UPDATE,
        Permission.NOTES_DELETE,
        Permission.NOTES_READ,
        Permission.EXPORT_DATA,
        Permission.USER_LIST,
    },
    UserRole.READONLY: {
        Permission.ENGAGEMENT_READ,
        Permission.TIMELINE_READ,
        Permission.NOTES_READ,
        Permission.USER_LIST,
    },
}


# =============================================================================
# Password Hashing
# =============================================================================

# Argon2 with secure defaults
# time_cost=3, memory_cost=65536 (64MB), parallelism=4
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2id"""
    return _password_hasher.hash(password)


def verify_password(password: str, hash: str) -> bool:
    """Verify a password against its hash"""
    try:
        _password_hasher.verify(hash, password)
        return True
    except (VerifyMismatchError, InvalidHash):
        return False


def password_needs_rehash(hash: str) -> bool:
    """Check if password hash needs to be updated (e.g., after config change)"""
    return _password_hasher.check_needs_rehash(hash)


# =============================================================================
# Session Management
# =============================================================================

class SessionData(BaseModel):
    """Data stored in a session"""
    user_id: str
    username: str
    role: UserRole
    created_at: datetime
    expires_at: datetime
    ip_address: str
    user_agent: str
    # Engagement access (None = all for admin, list for others)
    engagement_ids: Optional[List[str]] = None
    
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at
    
    def has_engagement_access(self, engagement_id: str) -> bool:
        """Check if session has access to a specific engagement"""
        if self.role == UserRole.ADMIN:
            return True
        if self.engagement_ids is None:
            return False
        return engagement_id in self.engagement_ids


class SessionStore:
    """
    In-memory session store with thread-safe operations.
    
    For multi-instance deployments, replace with Redis or database-backed store.
    """
    
    def __init__(self):
        self._sessions: Dict[str, SessionData] = {}
        self._user_sessions: Dict[str, Set[str]] = defaultdict(set)  # user_id -> session_ids
        self._lock = threading.RLock()
    
    def create(
        self,
        user_id: str,
        username: str,
        role: UserRole,
        ip_address: str,
        user_agent: str,
        engagement_ids: Optional[List[str]] = None,
    ) -> str:
        """Create a new session and return the session ID"""
        session_id = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        
        session = SessionData(
            user_id=user_id,
            username=username,
            role=role,
            created_at=now,
            expires_at=now + timedelta(hours=SecurityConfig.SESSION_EXPIRE_HOURS),
            ip_address=ip_address,
            user_agent=user_agent,
            engagement_ids=engagement_ids,
        )
        
        with self._lock:
            self._sessions[session_id] = session
            self._user_sessions[user_id].add(session_id)
        
        return session_id
    
    def get(self, session_id: str) -> Optional[SessionData]:
        """Get session data, returns None if not found or expired"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.is_expired():
                self._delete_session(session_id)
                return None
            return session
    
    def delete(self, session_id: str) -> bool:
        """Delete a session (logout)"""
        with self._lock:
            return self._delete_session(session_id)
    
    def _delete_session(self, session_id: str) -> bool:
        """Internal delete without lock"""
        session = self._sessions.pop(session_id, None)
        if session:
            self._user_sessions[session.user_id].discard(session_id)
            return True
        return False
    
    def delete_all_for_user(self, user_id: str) -> int:
        """Delete all sessions for a user (e.g., on password change)"""
        with self._lock:
            session_ids = list(self._user_sessions.get(user_id, set()))
            for sid in session_ids:
                self._delete_session(sid)
            return len(session_ids)
    
    def update_engagement_access(self, user_id: str, engagement_ids: List[str]):
        """Update engagement access for all sessions of a user"""
        with self._lock:
            for session_id in self._user_sessions.get(user_id, set()):
                session = self._sessions.get(session_id)
                if session:
                    session.engagement_ids = engagement_ids
    
    def cleanup_expired(self) -> int:
        """Remove expired sessions (call periodically)"""
        with self._lock:
            expired = [
                sid for sid, session in self._sessions.items()
                if session.is_expired()
            ]
            for sid in expired:
                self._delete_session(sid)
            return len(expired)
    
    def get_active_count(self) -> int:
        """Get count of active sessions"""
        with self._lock:
            return len(self._sessions)


# Global session store
session_store = SessionStore()


# =============================================================================
# CSRF Protection
# =============================================================================

def generate_csrf_token(session_id: str) -> str:
    """Generate a CSRF token tied to a session"""
    # HMAC-based token: prevents token forgery
    message = f"{session_id}:{SecurityConfig.SESSION_SECRET}"
    return hashlib.sha256(message.encode()).hexdigest()[:32]


def verify_csrf_token(session_id: str, token: str) -> bool:
    """Verify a CSRF token"""
    expected = generate_csrf_token(session_id)
    return secrets.compare_digest(expected, token)


# =============================================================================
# Rate Limiting
# =============================================================================

class RateLimiter:
    """
    Simple in-memory rate limiter using sliding window.
    
    For production multi-instance deployments, use Redis-based rate limiting.
    """
    
    def __init__(self):
        # key -> list of timestamps
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.RLock()
    
    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
        """
        Check if request is allowed.
        Returns (is_allowed, remaining_requests).
        """
        now = time.time()
        window_start = now - window_seconds
        
        with self._lock:
            # Remove old entries
            self._requests[key] = [
                ts for ts in self._requests[key]
                if ts > window_start
            ]
            
            current_count = len(self._requests[key])
            
            if current_count >= max_requests:
                return False, 0
            
            self._requests[key].append(now)
            return True, max_requests - current_count - 1
    
    def cleanup(self, max_age_seconds: int = 3600):
        """Remove stale entries (call periodically)"""
        now = time.time()
        cutoff = now - max_age_seconds
        
        with self._lock:
            empty_keys = []
            for key, timestamps in self._requests.items():
                self._requests[key] = [ts for ts in timestamps if ts > cutoff]
                if not self._requests[key]:
                    empty_keys.append(key)
            for key in empty_keys:
                del self._requests[key]


# Global rate limiters
login_rate_limiter = RateLimiter()
write_rate_limiter = RateLimiter()


def check_login_rate_limit(ip_address: str) -> bool:
    """Check if login attempt is allowed"""
    allowed, _ = login_rate_limiter.is_allowed(
        f"login:{ip_address}",
        SecurityConfig.RATE_LIMIT_LOGIN_ATTEMPTS,
        SecurityConfig.RATE_LIMIT_LOGIN_WINDOW,
    )
    return allowed


def check_write_rate_limit(user_id: str) -> bool:
    """Check if write request is allowed"""
    allowed, _ = write_rate_limiter.is_allowed(
        f"write:{user_id}",
        SecurityConfig.RATE_LIMIT_WRITE_REQUESTS,
        SecurityConfig.RATE_LIMIT_WRITE_WINDOW,
    )
    return allowed


# =============================================================================
# Input Validation and Sanitization
# =============================================================================

# Allowed HTML tags for markdown content (very restrictive)
ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 's', 'code', 'pre',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li',
    'blockquote', 'hr',
    'a', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
]

ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
    'th': ['align'],
    'td': ['align'],
}


def sanitize_markdown(content: str) -> str:
    """
    Sanitize markdown/HTML content to prevent XSS.
    Strips dangerous tags and attributes.
    """
    if not content:
        return content
    
    # Use bleach to clean HTML
    cleaned = bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True,
    )
    
    return cleaned


def sanitize_plain_text(text: str) -> str:
    """Escape HTML entities in plain text fields"""
    if not text:
        return text
    return html.escape(text)


def validate_username(username: str) -> bool:
    """Validate username format"""
    # 3-64 chars, alphanumeric, underscore, hyphen
    pattern = r'^[a-zA-Z][a-zA-Z0-9_-]{2,63}$'
    return bool(re.match(pattern, username))


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password meets minimum requirements.
    Returns (is_valid, error_message).
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if len(password) > 128:
        return False, "Password must be at most 128 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    return True, ""


# =============================================================================
# Authentication Schemas
# =============================================================================

class UserCreate(BaseModel):
    """Schema for creating a new user"""
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=12, max_length=128)
    display_name: str = Field(..., min_length=1, max_length=128)
    role: UserRole = UserRole.OPERATOR
    engagement_ids: Optional[List[str]] = None
    
    @field_validator('username')
    @classmethod
    def validate_username_format(cls, v):
        if not validate_username(v):
            raise ValueError(
                "Username must be 3-64 characters, start with a letter, "
                "and contain only letters, numbers, underscores, and hyphens"
            )
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        is_valid, error = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error)
        return v


class UserUpdate(BaseModel):
    """Schema for updating a user"""
    display_name: Optional[str] = Field(None, min_length=1, max_length=128)
    role: Optional[UserRole] = None
    engagement_ids: Optional[List[str]] = None
    is_active: Optional[bool] = None


class PasswordChange(BaseModel):
    """Schema for changing password"""
    current_password: str
    new_password: str = Field(..., min_length=12, max_length=128)
    
    @field_validator('new_password')
    @classmethod
    def validate_password(cls, v):
        is_valid, error = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error)
        return v


class LoginRequest(BaseModel):
    """Schema for login"""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Schema for login response"""
    user_id: str
    username: str
    display_name: str
    role: UserRole
    csrf_token: str


class UserResponse(BaseModel):
    """Schema for user data in responses"""
    id: str
    username: str
    display_name: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    engagement_ids: Optional[List[str]]
    
    class Config:
        from_attributes = True


# =============================================================================
# FastAPI Dependencies
# =============================================================================

# Cookie-based session authentication
session_cookie = APIKeyCookie(name=SecurityConfig.SESSION_COOKIE_NAME, auto_error=False)


def get_client_ip(request: Request) -> str:
    """Get client IP, handling proxies"""
    if SecurityConfig.BEHIND_PROXY:
        # Trust X-Forwarded-For header when behind proxy
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first IP (client IP)
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def get_current_session(
    request: Request,
    session_id: Optional[str] = Depends(session_cookie),
) -> SessionData:
    """
    Dependency to get current authenticated session.
    Raises 401 if not authenticated.
    """
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    
    session = session_store.get(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
        )
    
    return session


async def get_optional_session(
    request: Request,
    session_id: Optional[str] = Depends(session_cookie),
) -> Optional[SessionData]:
    """
    Dependency to get current session if present, None otherwise.
    For endpoints that work with or without auth.
    """
    if not session_id:
        return None
    return session_store.get(session_id)


def require_permission(permission: Permission):
    """
    Dependency factory to require a specific permission.
    Usage: Depends(require_permission(Permission.ENGAGEMENT_CREATE))
    """
    async def check_permission(session: SessionData = Depends(get_current_session)):
        if permission not in ROLE_PERMISSIONS.get(session.role, set()):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value}",
            )
        return session
    return check_permission


def require_engagement_access(engagement_id_param: str = "engagement_id"):
    """
    Dependency factory to require access to a specific engagement.
    Extracts engagement_id from path parameters.
    """
    async def check_access(
        request: Request,
        session: SessionData = Depends(get_current_session),
    ):
        engagement_id = request.path_params.get(engagement_id_param)
        if not engagement_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Engagement ID required",
            )
        
        if not session.has_engagement_access(engagement_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this engagement",
            )
        
        return session
    return check_access


def require_csrf(request: Request, session: SessionData = Depends(get_current_session)):
    """
    Dependency to verify CSRF token for state-changing requests.
    Token should be in X-CSRF-Token header.
    """
    # Skip CSRF check for safe methods
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return session
    
    csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token required",
        )
    
    # Get session ID from cookie to verify token
    session_id = request.cookies.get(SecurityConfig.SESSION_COOKIE_NAME)
    if not session_id or not verify_csrf_token(session_id, csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token",
        )
    
    return session


def rate_limit_writes(session: SessionData = Depends(get_current_session)):
    """Dependency to rate limit write operations"""
    if not check_write_rate_limit(session.user_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please slow down.",
        )
    return session


# =============================================================================
# Cookie Helpers
# =============================================================================

def set_session_cookie(response: Response, session_id: str):
    """Set secure session cookie on response"""
    response.set_cookie(
        key=SecurityConfig.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=SecurityConfig.BEHIND_PROXY,  # Secure only when behind TLS-terminating proxy
        samesite="lax",
        max_age=SecurityConfig.SESSION_EXPIRE_HOURS * 3600,
        path="/",
    )


def clear_session_cookie(response: Response):
    """Clear session cookie on logout"""
    response.delete_cookie(
        key=SecurityConfig.SESSION_COOKIE_NAME,
        path="/",
    )


# =============================================================================
# Security Headers Middleware Helper
# =============================================================================

def get_security_headers() -> Dict[str, str]:
    """Get security headers to add to responses"""
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }
    
    # Add stricter CSP in production
    if not SecurityConfig.DEBUG_MODE:
        headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none';"
        )
    
    return headers


# =============================================================================
# CORS Configuration Helper
# =============================================================================

def get_cors_origins() -> List[str]:
    """Get allowed CORS origins based on configuration"""
    if SecurityConfig.DEBUG_MODE and not SecurityConfig.CORS_ALLOWED_ORIGINS:
        # In debug mode without explicit config, allow common dev origins
        return [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ]
    
    if not SecurityConfig.CORS_ALLOWED_ORIGINS:
        # No origins configured = same-origin only (empty list)
        return []
    
    # Never allow wildcard in production
    origins = [o for o in SecurityConfig.CORS_ALLOWED_ORIGINS if o != "*"]
    
    return origins


# =============================================================================
# Initialization
# =============================================================================

def init_security():
    """Initialize security module - call on startup"""
    SecurityConfig.load()
    print(f"[Security] Debug mode: {SecurityConfig.DEBUG_MODE}")
    print(f"[Security] Session expiry: {SecurityConfig.SESSION_EXPIRE_HOURS} hours")
    print(f"[Security] CORS origins: {get_cors_origins() or '(same-origin only)'}")
    print(f"[Security] Behind proxy: {SecurityConfig.BEHIND_PROXY}")
