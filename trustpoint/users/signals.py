import threading
import sys
from django.core.signals import request_started
from django.db.models.signals import post_migrate, post_init
from django.dispatch import receiver
from users.scheduler import TaskScheduler
import logging

logger = logging.getLogger('tp.users')

tasks_initialized = False

@receiver(request_started)
def trigger_tasks_on_first_request(sender, **kwargs):
    """Trigger tasks after the first HTTP request is processed when running the server."""
    global tasks_initialized

    if 'runserver' in sys.argv and not tasks_initialized:
        try:
            logger.debug("Triggering periodic tasks after server startup on the first request...")
            tasks_initialized = True
            scheduler = TaskScheduler()
            threading.Thread(target=scheduler.setup_periodic_tasks, args=(5,), daemon=True).start()
            logger.debug("Periodic tasks triggered successfully after server startup.")
        except Exception as e:
            logger.error(f"Failed to trigger periodic tasks after server startup: {e}")
