"""Django apps module which defines the app configuration."""
from django.apps import AppConfig
import logging

logger = logging.getLogger('tp.users')

class UsersConfig(AppConfig):
    """App configuration for the users app."""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'


