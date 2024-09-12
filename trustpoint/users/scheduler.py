import logging
from datetime import datetime

from django_q.models import Schedule

logger = logging.getLogger('tp.users')

def delete_existing_schedules():
    """
    Delete all existing schedules in Django-Q2.
    """
    Schedule.objects.all().delete()
    logger.info("All existing schedules have been deleted.")

def setup_periodic_tasks():
    """
    Function to set up the tasks for Django-Q2.
    This ensures that tasks are correctly scheduled and not duplicated.
    """

    task_name = 'setup_trustpoint_notifications'
    if not Schedule.objects.filter(name=task_name).exists():
        Schedule.objects.create(
            name=task_name,
            func='users.tasks.setup_trustpoint_notifications',
            schedule_type=Schedule.ONCE,
            next_run=datetime.now(),
            repeats=1,
        )
        logger.info(f"Scheduled '{task_name}' to run once")

    periodic_tasks = [
        'users.tasks.check_system_health',
        'users.tasks.check_for_security_vulnerabilities',
        'users.tasks.check_certificate_validity',
        'users.tasks.check_issuing_ca_validity',
        'users.tasks.check_expired_certificates',
        'users.tasks.check_expired_issuing_cas',
        'users.tasks.check_domain_issuing_ca',
        'users.tasks.check_non_onboarded_devices',
        'users.tasks.check_devices_with_failed_onboarding',
        'users.tasks.check_devices_with_revoked_certificates',
        'users.tasks.check_for_weak_signature_algorithms',
        'users.tasks.check_for_insufficient_key_length',
        'users.tasks.check_for_weak_ecc_curves',
        'users.tasks.test_task'
    ]

    for task in periodic_tasks:
        task_name = task.split('.')[-1]  # Use the function name as the task name
        if not Schedule.objects.filter(name=task_name).exists():
            Schedule.objects.create(
                name=task_name,
                func=task,
                schedule_type=Schedule.MINUTES,
                minutes=10,  # Execute every 10 minutes
                repeats=-1,  # Infinite repeats
            )
            logger.info(f"Scheduled '{task_name}' to run every 10 minutes")
        else:
            logger.info(f"'{task_name}' is already scheduled")
