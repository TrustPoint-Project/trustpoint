"""Django apps module which defines the app configuration."""
import sys

from django.apps import AppConfig
from django.db.models.signals import post_migrate
import logging

from users.scheduler import TaskScheduler

logger = logging.getLogger('tp.users')


class UsersConfig(AppConfig):
    """App configuration for the users app."""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'

    def ready(self):
        post_migrate.connect(self.setup_periodic_tasks_after_migrations, sender=self)
        #post_migrate.connect(self.trigger_tasks_on_startup, sender=self)

        if 'runserver' in sys.argv:
            self.trigger_tasks_on_startup()


    def setup_periodic_tasks_after_migrations(self, **kwargs):
        """Setup periodic tasks after migrations are applied."""
        try:
            logger.debug("Setting up periodic tasks after migrations...")
            scheduler = TaskScheduler()
            scheduler.schedule_one_time_task()
            scheduler.setup_periodic_tasks()
            logger.debug("Periodic tasks set up successfully.")
        except Exception as e:
            logger.error(f"Failed to set up periodic tasks: {e}")

    def trigger_tasks_on_startup(self):
        """Method to trigger tasks when the server starts."""
        try:
            logger.debug("Triggering periodic tasks on server startup...")
            scheduler = TaskScheduler()
            scheduler.trigger_periodic_tasks()
            logger.debug("Periodic tasks triggered successfully on server startup.")
        except Exception as e:
            logger.error(f"Failed to trigger periodic tasks on server startup: {e}")


