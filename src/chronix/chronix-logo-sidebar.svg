# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Tyrrell Brewster

"""
Centralized Secure Filesystem Access Module for Chronix.

ALL filesystem operations involving user-influenced paths MUST go through
this module. Direct use of Path() / open() / os.path.join() with user input
is prohibited elsewhere in the codebase.

Defense-in-depth layers:
    L1  Unicode normalization (NFKC) — blocks homoglyph/fullwidth bypasses
    L2  Null-byte and control-character rejection
    L3  Strict filename allowlist (regex)
    L4  Canonical path resolution + containment (is_relative_to)
    L5  Full-chain symlink walk (every path component, using lstat)
    L6  Regular-file-only enforcement (rejects dirs, devices, pipes, sockets)
    L7  O_NOFOLLOW + fstat fd-based open — eliminates TOCTOU race window
    L8  Content-Disposition sanitization — prevents header injection
    L9  Structured telemetry logging with severity levels

References:
    CWE-22   Improper Limitation of a Pathname to a Restricted Directory
    CWE-59   Improper Link Resolution Before File Access
    CWE-158  Improper Neutralization of Null Byte or NUL Character
    CWE-367  Time-of-check Time-of-use (TOCTOU) Race Condition
    CWE-176  Improper Handling of Unicode Encoding
    CWE-113  Improper Neutralization of CRLF Sequences in HTTP Headers
"""

from __future__ import annotations

import logging
import os
import re
import stat
import unicodedata
from pathlib import Path
from typing import IO, Optional

from fastapi import HTTPException

logger = logging.getLogger("chronix.security.filesystem")

# ── L3: Strict Filename Allowlist ───────────────────────────────────────
#
# After NFKC normalization, the filename must match this pattern:
#   - Starts with alphanumeric
#   - Body: alphanumeric, hyphen, underscore only
#   - Optionally one dot followed by 1-10 alphanumeric extension chars
#
# This blocks every known bypass class:
#   Path separators (/ \), parent refs (..), URL encoding (%), null bytes,
#   fullwidth Unicode, control chars, spaces, shell metacharacters,
#   dotfiles (.env), device names (CON, NUL on Windows).
#
VALID_FILENAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]*(\.[a-zA-Z0-9]{1,10})?$")

MAX_FILENAME_LENGTH = 255

# Unicode codepoints that normalize to path-dangerous ASCII under NFKC.
# Reject these explicitly before normalization as an additional belt.
_UNICODE_SLASH_CODEPOINTS = frozenset({
    "\uff0f",  # ／ FULLWIDTH SOLIDUS           → /
    "\uff3c",  # ＼ FULLWIDTH REVERSE SOLIDUS   → \
    "\u2044",  # ⁄  FRACTION SLASH
    "\u2215",  # ∕  DIVISION SLASH
    "\ufe68",  # ﹨ SMALL REVERSE SOLIDUS       → \
    "\u29f8",  # ⧸  BIG SOLIDUS
    "\u29f9",  # ⧹  BIG REVERSE SOLIDUS
})

# Windows reserved device names (block even on Linux for portability)
_WINDOWS_RESERVED = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})


class PathSecurityError(Exception):
    """Raised when a path security violation is detected."""

    def __init__(self, message: str, *, user_input: str = "", detail: str = ""):
        super().__init__(message)
        self.user_input = user_input
        self.detail = detail


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════


def validate_filename(filename: str) -> str:
    """
    Validate an untrusted filename through layers L1-L3.

    Returns the NFKC-normalized, validated filename.

    Raises:
        PathSecurityError on any validation failure.
    """
    # ── L2: Null bytes / control characters ──────────────────────────
    if not filename:
        raise PathSecurityError("Empty filename", user_input="", detail="Filename must not be empty")

    if "\x00" in filename or "%00" in filename:
        raise PathSecurityError(
            "Null byte in filename",
            user_input=repr(filename),
            detail="Filename contains null bytes",
        )

    # Reject any ASCII control character (0x00-0x1F, 0x7F)
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in filename):
        raise PathSecurityError(
            "Control character in filename",
            user_input=repr(filename),
            detail="Filename contains control characters",
        )

    # ── L1: Unicode normalization ────────────────────────────────────
    # Check for known dangerous Unicode codepoints BEFORE normalization
    for c in filename:
        if c in _UNICODE_SLASH_CODEPOINTS:
            raise PathSecurityError(
                "Unicode path separator in filename",
                user_input=repr(filename),
                detail=f"Filename contains Unicode path separator U+{ord(c):04X}",
            )

    # NFKC normalization collapses fullwidth/compatibility forms to ASCII.
    # After this, ＡＢＣ → ABC, ．．／ → ../ etc.
    filename = unicodedata.normalize("NFKC", filename)

    # ── L3: Length ───────────────────────────────────────────────────
    if len(filename) > MAX_FILENAME_LENGTH:
        raise PathSecurityError(
            "Filename too long",
            user_input=filename[:50] + "...",
            detail=f"Filename exceeds {MAX_FILENAME_LENGTH} characters",
        )

    # ── L3: Structural checks (explicit, before regex) ──────────────
    if "/" in filename or "\\" in filename:
        raise PathSecurityError(
            "Path separator in filename",
            user_input=repr(filename),
            detail="Filename contains path separators",
        )

    if ".." in filename:
        raise PathSecurityError(
            "Directory traversal in filename",
            user_input=repr(filename),
            detail="Filename contains parent directory reference",
        )

    # ── L3: Windows reserved device names ────────────────────────────
    stem = filename.split(".")[0].upper()
    if stem in _WINDOWS_RESERVED:
        raise PathSecurityError(
            "Reserved device name",
            user_input=repr(filename),
            detail=f"Filename uses reserved name: {stem}",
        )

    # ── L3: Allowlist regex ──────────────────────────────────────────
    if not VALID_FILENAME_RE.match(filename):
        raise PathSecurityError(
            "Invalid filename characters",
            user_input=repr(filename),
            detail="Filename contains disallowed characters",
        )

    return filename


def secure_resolve(
    base_dir: Path,
    user_input: str,
    *,
    must_exist: bool = False,
    allow_symlinks: bool = False,
    request_context: Optional[dict] = None,
) -> Path:
    """
    Securely resolve a user-supplied filename within a base directory.

    Applies layers L1-L6. Does NOT open the file (no fd - use secure_open
    when you need to read file contents to eliminate TOCTOU).

    This function is appropriate for:
      - Write paths (upload destination, deletion target)
      - Existence checks
      - Path construction before handing to secure_open()

    For serving files to users, prefer secure_open() which adds L7.

    Args:
        base_dir:        Trusted base directory.
        user_input:      Untrusted filename from user / database.
        must_exist:      Raise 404 if the resolved path does not exist.
        allow_symlinks:  Skip symlink checks (use with extreme caution).
        request_context: Optional dict {user_id, ip, endpoint} for logging.

    Returns:
        Resolved, validated Path guaranteed to be within base_dir.

    Raises:
        HTTPException 400 - filename validation failed
        HTTPException 403 - path traversal, symlink, or special-file detected
        HTTPException 404 - must_exist=True and file missing
    """
    ctx = request_context or {}

    # ── L1-L3: Filename validation (includes NFKC normalization) ─────
    try:
        validated = validate_filename(user_input)
    except PathSecurityError as e:
        _log_security_event(
            "filename_rejected",
            reason=str(e),
            user_input=user_input,
            base_dir=str(base_dir),
            **ctx,
        )
        raise HTTPException(status_code=400, detail="Invalid filename")

    # ── L4: Canonical resolution + containment ───────────────────────
    resolved_base = base_dir.resolve(strict=False)
    resolved_path = (base_dir / validated).resolve(strict=False)

    if not resolved_path.is_relative_to(resolved_base):
        _log_security_event(
            "path_traversal_blocked",
            reason="Resolved path escapes base directory",
            user_input=user_input,
            base_dir=str(resolved_base),
            resolved=str(resolved_path),
            **ctx,
        )
        raise HTTPException(status_code=403, detail="Invalid file path")

    # Depth check: only allow flat files directly inside base_dir
    relative = resolved_path.relative_to(resolved_base)
    if len(relative.parts) != 1:
        _log_security_event(
            "subdirectory_traversal_blocked",
            reason=f"Path has {len(relative.parts)} components, expected 1",
            user_input=user_input,
            base_dir=str(resolved_base),
            **ctx,
        )
        raise HTTPException(status_code=403, detail="Invalid file path")

    # ── L5: Full-chain symlink walk ──────────────────────────────────
    #
    # Check the UNresolved path: .resolve() follows symlinks transparently,
    # so resolved_path.is_symlink() would always return False. We must
    # walk the original constructed path component-by-component using
    # lstat() which does not follow symlinks.
    #
    if not allow_symlinks:
        original_path = base_dir / validated
        if original_path.exists(follow_symlinks=False):
            if original_path.is_symlink():
                _log_security_event(
                    "symlink_blocked",
                    reason="Symlink at target path",
                    user_input=user_input,
                    base_dir=str(resolved_base),
                    target=str(os.readlink(original_path)),
                    **ctx,
                )
                raise HTTPException(status_code=403, detail="Invalid file path")

        # Walk every component from base_dir through each part
        check = resolved_base
        for part in relative.parts:
            check = check / part
            try:
                st = os.lstat(check)
                if stat.S_ISLNK(st.st_mode):
                    _log_security_event(
                        "symlink_in_chain_blocked",
                        reason=f"Symlink in path chain at: {check}",
                        user_input=user_input,
                        base_dir=str(resolved_base),
                        **ctx,
                    )
                    raise HTTPException(status_code=403, detail="Invalid file path")
            except FileNotFoundError:
                pass  # Component doesn't exist yet (write path)

    # ── L6: Regular-file enforcement ─────────────────────────────────
    if resolved_path.exists():
        try:
            st = os.lstat(resolved_path)
        except OSError:
            raise HTTPException(status_code=403, detail="Invalid file path")

        if not stat.S_ISREG(st.st_mode):
            if stat.S_ISDIR(st.st_mode):
                detail = "Path is a directory"
            elif stat.S_ISLNK(st.st_mode):
                detail = "Path is a symbolic link"
            elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
                detail = "Path is a device file"
            elif stat.S_ISFIFO(st.st_mode):
                detail = "Path is a FIFO/pipe"
            elif stat.S_ISSOCK(st.st_mode):
                detail = "Path is a socket"
            else:
                detail = "Path is not a regular file"

            _log_security_event(
                "special_file_blocked",
                reason=detail,
                user_input=user_input,
                base_dir=str(resolved_base),
                file_mode=oct(st.st_mode),
                **ctx,
            )
            raise HTTPException(status_code=403, detail="Invalid file path")

    # ── Existence check ──────────────────────────────────────────────
    if must_exist and not resolved_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    return resolved_path


def secure_open(
    base_dir: Path,
    user_input: str,
    *,
    request_context: Optional[dict] = None,
) -> IO[bytes]:
    """
    L7: Open a file using fd-based access with O_NOFOLLOW to eliminate TOCTOU.

    This is the ONLY safe way to read file contents for serving to users.
    It atomically opens and verifies the file in a single syscall, closing
    the race window between check and use.

    The returned file object is ready for streaming. The caller is
    responsible for closing it (use ``with`` or pass to StreamingResponse).

    Args:
        base_dir:        Trusted base directory.
        user_input:      Untrusted filename from user / database.
        request_context: Optional dict {user_id, ip, endpoint} for logging.

    Returns:
        An open file object in binary read mode.

    Raises:
        HTTPException 400 - filename validation failed
        HTTPException 403 - path traversal, symlink, TOCTOU, or special file
        HTTPException 404 - file not found
    """
    ctx = request_context or {}

    # Run through L1-L6 first
    resolved = secure_resolve(
        base_dir,
        user_input,
        must_exist=True,
        allow_symlinks=False,
        request_context=ctx,
    )

    # ── L7: Atomic fd-based open with O_NOFOLLOW ────────────────────
    #
    # Even after all Path-level checks pass, a race condition exists:
    # an attacker who can write to the directory could swap the real file
    # for a symlink between our check and the open() call.
    #
    # O_NOFOLLOW causes the open to FAIL if the final path component is
    # a symlink, closing the TOCTOU window atomically at the kernel level.
    #
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = -1
    try:
        fd = os.open(str(resolved), flags)
    except OSError as e:
        import errno as errno_mod
        if e.errno == errno_mod.ELOOP:
            _log_security_event(
                "toctou_symlink_blocked",
                reason="O_NOFOLLOW detected symlink at open() time (TOCTOU race)",
                user_input=user_input,
                base_dir=str(base_dir),
                **ctx,
            )
            raise HTTPException(status_code=403, detail="Invalid file path")
        _log_security_event(
            "file_open_failed",
            reason=str(e),
            user_input=user_input,
            base_dir=str(base_dir),
            **ctx,
        )
        raise HTTPException(status_code=404, detail="File not found")

    # ── L6 recheck via fstat: verify fd points to a regular file ─────
    # fstat operates on the open fd, so it cannot be raced.
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            _log_security_event(
                "fd_special_file_blocked",
                reason=f"fd points to non-regular file (mode={oct(st.st_mode)})",
                user_input=user_input,
                base_dir=str(base_dir),
                **ctx,
            )
            raise HTTPException(status_code=403, detail="Invalid file path")
    except OSError:
        os.close(fd)
        raise HTTPException(status_code=403, detail="Invalid file path")

    # Wrap raw fd in a Python file object for streaming
    return os.fdopen(fd, "rb")


def secure_serve_path(
    base_dir: Path,
    stored_filename: str,
    *,
    request_context: Optional[dict] = None,
) -> Path:
    """
    Validate a path for serving (L1-L6 only, no fd).

    Use this when you need a validated Path but will handle the actual
    open/read yourself (e.g., for zf.write in ZIP export).

    For HTTP file serving, prefer secure_open() -> StreamingResponse.
    """
    return secure_resolve(
        base_dir,
        stored_filename,
        must_exist=True,
        request_context=request_context,
    )


def sanitize_content_disposition(display_name: str) -> str:
    """
    L8: Sanitize a display filename for the Content-Disposition header.

    Prevents HTTP header injection via CRLF sequences and ensures the
    filename is safe for all clients.
    """
    # Strip control characters and CRLF
    name = re.sub(r'[\x00-\x1f\x7f\r\n]', '', display_name)
    # Remove characters dangerous in headers and filenames
    name = re.sub(r'[<>:"/\\|?*\'`]', '_', name)
    # Collapse multiple underscores
    name = re.sub(r'_+', '_', name).strip('_')
    if not name:
        name = "download"
    if len(name) > 200:
        name = name[:200]
    return name


# ═══════════════════════════════════════════════════════════════════════
# TELEMETRY (L9)
# ═══════════════════════════════════════════════════════════════════════


def _log_security_event(
    event_type: str,
    reason: str,
    user_input: str,
    base_dir: str,
    user_id: str = "unknown",
    ip: str = "unknown",
    endpoint: str = "unknown",
    **extra,
) -> None:
    """
    Structured security event logging.

    TOCTOU races and symlink detections use ERROR level as they
    indicate active exploitation attempts.
    """
    severity = "high" if "toctou" in event_type or "symlink" in event_type else "medium"
    level = logging.ERROR if severity == "high" else logging.WARNING

    logger.log(
        level,
        "Filesystem security event [%s]: %s",
        event_type,
        reason,
        extra={
            "event_type": f"filesystem_access_denied.{event_type}",
            "severity": severity,
            "reason": reason,
            "user_input": repr(user_input)[:200],
            "base_dir": base_dir,
            "user_id": user_id,
            "ip": ip,
            "endpoint": endpoint,
            **{k: v for k, v in extra.items() if k not in ("user_id", "ip", "endpoint")},
        },
    )
