# -*- coding: utf-8 -*-

"""
Azauthlib: Azure Authentication and Token Management Library
"""

__version__ = "1.3.1b1"

#────────── Project-specific imports (directly from this project's source code) ───────────────────────────────────  
from .authentication import Authentication

# ─── Define module’s public interface ───────────────────────────
__all__ = ["Authentication", "__version__"]
