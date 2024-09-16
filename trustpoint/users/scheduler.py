import logging
from datetime import datetime
from django.utils import timezone

logger = logging.getLogger('tp.users')

class TaskScheduler:
    """
    Class responsible for setting up, deleting, and manually triggering periodic tasks.
    It also handles one-time tasks and avoids duplicating schedules.
    """

    def __init__(self):
        # List of periodic tasks to trigger or schedule
        self.periodic_tasks = [
            'users.tasks.check_system_health',
            'users.tasks.check_for_security_vulnerabilities',
            'users.tasks.check_certificate_validity',
            'users.tasks.check_issuing_ca_validity',
            'users.tasks.check_domain_issuing_ca',
            'users.tasks.check_non_onboarded_devices',
            'users.tasks.check_devices_with_failed_onboarding',
            'users.tasks.check_devices_with_revoked_certificates',
            'users.tasks.check_for_weak_signature_algorithms',
            'users.tasks.check_for_insufficient_key_length',
            'users.tasks.check_for_weak_ecc_curves',
        ]

    def delete_existing_schedules(self):
        """
        Delete all existing schedules in Django-Q.
        """
        from django_q.models import Schedule
        try:
            Schedule.objects.all().delete()
            logger.info("All existing schedules have been deleted.")
        except Exception as e:
            logger.error(f"Failed to delete existing schedules: {e}")

    def setup_periodic_tasks(self):
        """
        Set up periodic tasks to run every 10 minutes. Tasks will start immediately if not already scheduled.
        """
        from django_q.models import Schedule
        from django_q.tasks import async_task
        logger.info("Setting up periodic tasks...")
        minutes = 1

        # Loop through the periodic tasks and schedule them
        for task in self.periodic_tasks:
            task_name = task.split('.')[-1]  # Use the function name as the task name
            if not Schedule.objects.filter(name=task_name).exists():
                try:
                    Schedule.objects.create(
                        name=task_name,
                        func=task,
                        schedule_type=Schedule.MINUTES,
                        minutes=minutes,  # Execute every 10 minutes
                        repeats=-1,  # Infinite repeats
                        next_run=timezone.now(),
                    )
                    logger.info(f"Scheduled '{task_name}' to run every {minutes} minutes, starting immediately")
                except Exception as e:
                    logger.error(f"Failed to schedule '{task_name}': {e}")
            else:
                async_task(task)
                logger.info(f"'{task_name}' is already scheduled")

    def schedule_one_time_task(self):
        """
        Schedule a one-time task if not already scheduled.
        """
        from django_q.models import Schedule
        task_name = 'setup_trustpoint_notifications'
        if not Schedule.objects.filter(name=task_name).exists():
            try:
                Schedule.objects.create(
                    name=task_name,
                    func='users.tasks.setup_trustpoint_notifications',
                    schedule_type=Schedule.ONCE,
                    next_run=timezone.now(),
                    repeats=1,
                )
                logger.info(f"Scheduled '{task_name}' to run once")
            except Exception as e:
                logger.error(f"Failed to schedule one-time task '{task_name}': {e}")
        else:
            logger.info(f"One-time task '{task_name}' is already scheduled")

    def trigger_periodic_tasks(self):
        """
        Manually trigger all periodic tasks once, without modifying their schedules.
        """
        from django_q.tasks import async_task
        logger.info("Manually triggering all periodic tasks.")
        for task in self.periodic_tasks:
            try:
                logger.info(f"Triggering '{task}' task asynchronously.")
                async_task(task)
            except Exception as e:
                logger.error(f"Failed to trigger task '{task}': {e}")
        logger.info("All periodic tasks triggered successfully.")