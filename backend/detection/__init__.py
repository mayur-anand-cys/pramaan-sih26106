# Detection subpackage init
"""Detection utilities for email authentication and XAI contradiction detection.
"""
from backend.detection import auth_check
from backend.detection import xai
from backend.detection import attachment_analyzer

__all__ = ["auth_check", "xai", "attachment_analyzer"]
