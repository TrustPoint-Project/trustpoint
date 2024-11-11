from django.core.management.base import BaseCommand
from users.scheduler import TaskScheduler
import logging

logger = logging.getLogger('tp.users')

class Command(BaseCommand):
    help = 'Triggers the periodic tasks for the users app.'

    def handle(self, *args, **kwargs):
        logger.debug("Starting periodic tasks...")
        scheduler = TaskScheduler()
        scheduler.trigger_all_tasks_once()
        logger.debug("Periodic tasks started.")
