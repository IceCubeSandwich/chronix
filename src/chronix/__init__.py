# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Tyrrell Brewster

"""
Chronix

Self-hosted collaborative workspace for security operations.
"""

__version__ = "1.0.0"
__author__ = "Tyrrell Brewster"
__email__ = "0xtb.sh@proton.me"
__license__ = "AGPL-3.0-only"

from .server import app
from .models import Engagement, TimelineEntry, User, NotePage

__all__ = ["app", "Engagement", "TimelineEntry", "User", "NotePage", "__version__"]
