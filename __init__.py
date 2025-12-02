"""
Azauthlib: Azure Authentication and Token Management Library
"""

# Library version
__version__ = "1.2.2b1"

# Explicit imports
from .authentication import Authentication

# Define what gets exported on "from azauthlib import *"
__all__ = [
    "Authentication",
    "__version__",
]
