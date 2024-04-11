"""Shared Ninja schema definitions."""

from ninja import Schema


class ErrorSchema(Schema):
    """Error response schema."""
    error: str
    detail: str = None  # Optional, e.g. for exception details

class SuccessSchema(Schema):
    """Success response schema."""
    success: bool
    message: str = None
