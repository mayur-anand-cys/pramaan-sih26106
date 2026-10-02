# Detection subpackage init
"""Detection utilities for email authentication, thread hijacking,
body-embedded header spoofing, and XAI contradiction detection.
"""
from backend.detection import auth_check
from backend.detection import xai
from backend.detection import thread_hijack
from backend.detection import body_header_check

__all__ = ["auth_check", "xai", "thread_hijack", "body_header_check"]
