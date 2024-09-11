"""Core of the Trustpoint Django Application."""

from .celery import app as celery_app

__all__ = ['celery_app']