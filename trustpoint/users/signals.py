import threading
import os
from django.db.backends.signals import connection_created
from django.dispatch import receiver
from users.scheduler import TaskScheduler
import logging

logger = logging.getLogger('tp.users')

tasks_initialized = False

@receiver(connection_created)
def trigger_tasks_on_startup(sender, **kwargs):
    """Trigger tasks after the first HTTP request is processed when running the server."""
    global tasks_initialized
    
    if tasks_initialized:
        return

    if not os.environ.get('TRUSTPOINT_RUNNING') and \
            not os.environ.get('RUN_MAIN') and \
            not os.environ.get('WERKZEUG_RUN_MAIN'):
        # Just helper process, not running startup code
        return

    try:
        logger.debug("Triggering periodic tasks after server startup...")
        tasks_initialized = True
        scheduler = TaskScheduler()
        threading.Thread(target=scheduler.setup_periodic_tasks, args=(5,), daemon=True).start()
        logger.debug("Periodic tasks triggered successfully after server startup.")
    except Exception as e:
        logger.error(f"Failed to trigger periodic tasks after server startup: {e}")
