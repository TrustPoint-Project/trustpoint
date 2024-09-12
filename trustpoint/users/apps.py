"""Django apps module which defines the app configuration."""

from django.apps import AppConfig
from django.db.models.signals import post_migrate
import logging

logger = logging.getLogger('tp.users')


class UsersConfig(AppConfig):
    """App configuration for the users app."""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'

    def ready(self):
        post_migrate.connect(self.setup_periodic_tasks_after_migrations, sender=self)

    def setup_periodic_tasks_after_migrations(self, **kwargs):
        """Setup periodic tasks after migrations are applied."""
        from users.scheduler import setup_periodic_tasks
        try:
            logger.debug("Setting up periodic tasks after migrations...")
            setup_periodic_tasks()
            logger.debug("Periodic tasks set up successfully.")
        except Exception as e:
            logger.error(f"Failed to set up periodic tasks: {e}")


