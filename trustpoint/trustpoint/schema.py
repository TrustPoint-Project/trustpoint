"""Shared Ninja schema definitions."""

from ninja import Schema

class ErrorSchema(Schema):
    error: str

class SuccessSchema(Schema):
    success: bool