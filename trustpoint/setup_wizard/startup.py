from __future__ import annotations

import logging
import os
import sys
import threading

from django.db.backends.signals import connection_created

from discovery.mdns import TrustpointMDNSResponder
from pki.tasks import start_crl_generation_thread
from users.scheduler import TaskScheduler

log = logging.getLogger('tp.startup')

from typing import Any


class StartupTaskManager:
    _db_tasks_started = False
    _mdns_instance: TrustpointMDNSResponder | None = None

    @staticmethod
    def running_dev_server() -> bool:
        """True if executing the development server (manage.py runserver or runserver_plus)"""
        return bool(os.environ.get('RUN_MAIN')) or bool(os.environ.get('WERKZEUG_RUN_MAIN'))

    @staticmethod
    def running_wsgi_server() -> bool:
        """True if executing the WSGI server (Apache, ...)"""
        return 'django.core.wsgi' in sys.modules

    @staticmethod
    def running_server() -> bool:
        """True if running any server (dev or wsgi)"""
        return StartupTaskManager.running_wsgi_server() or StartupTaskManager.running_dev_server()

    @staticmethod
    def handle_startup_tasks():
        """Starts periodic tasks, called by ready in startup.apps"""
        if not StartupTaskManager.running_dev_server and not StartupTaskManager.running_wsgi_server:
            # Just helper process, not running startup code
            return

        log.info('Running startup tasks')

        _mdns_instance = TrustpointMDNSResponder()
        connection_created.connect(StartupTaskManager.handle_startup_db_tasks)

    @staticmethod
    def handle_startup_db_tasks(sender: Any, **kwargs: Any):
        """Handle startup tasks that require an established database connection"""
        if StartupTaskManager._db_tasks_started:
            return

        StartupTaskManager._db_tasks_started = True
        connection_created.disconnect(StartupTaskManager.handle_startup_db_tasks)

        log.info('Initial database connection established, triggering tasks...')

        start_crl_generation_thread()

        try:
            scheduler = TaskScheduler()
            threading.Thread(target=scheduler.setup_periodic_tasks, args=(5,), daemon=True).start()
            log.debug("Periodic tasks triggered successfully after server startup.")
        except Exception as e:
            log.error(f"Failed to trigger periodic tasks after server startup: {e}")

    @staticmethod
    def handle_shutdown_tasks():
        """Handle shutdown tasks, called by SIGINT/SIGTERM handlers"""
        log.info('Running shutdown tasks')

        if StartupTaskManager._mdns_instance:
            StartupTaskManager._mdns_instance.unregister()

    def __init__(self) -> None:
        raise TypeError('Not permitted to create instances of StartupTaskManager')