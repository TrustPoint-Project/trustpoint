"""Shared Ninja schema definitions."""

from ninja import Schema

class ErrorSchema(Schema):
    error: str
    detail: str = None  # Optional, e.g. for exception details

class SuccessSchema(Schema):
    success: bool
    message: str = None