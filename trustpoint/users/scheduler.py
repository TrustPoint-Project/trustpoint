import logging
from django_celery_beat.models import CrontabSchedule, PeriodicTask, IntervalSchedule

logger = logging.getLogger('tp.users')

def setup_periodic_tasks():
    # Create or get the Crontab schedule
    # schedule, created = CrontabSchedule.objects.get_or_create(
    #     minute="*",  # Every minute
    #     hour="*",  # Every hour
    #     day_of_week="*",  # Every day of the week
    #     day_of_month="*",  # Every day of the month
    #     month_of_year="*",  # Every month
    # )

    schedule, created = IntervalSchedule.objects.get_or_create(
        every=10,
        period=IntervalSchedule.SECONDS,
    )

    if created:
        logger.debug("New Crontab schedule created: Every minute")
    else:
        logger.debug("Existing Crontab schedule used: Every minute")

    # Create or update the periodic task to check certificate validity
    task_name = 'Check Certificate Validity'
    periodic_task, task_created = PeriodicTask.objects.update_or_create(
        name=task_name,
        defaults={
            'interval': schedule,
            'task': 'users.tasks.check_certificate_validity',
            'enabled': True
        }
    )

    if task_created:
        logger.debug(f"Created new periodic task: {task_name}")
    else:
        logger.debug(f"Updated existing periodic task: {task_name}")

    # Create or update the periodic task to check Issuing CA validity
    task_name_ca = 'Check Issuing CA Validity'
    periodic_task_ca, task_created_ca = PeriodicTask.objects.update_or_create(
        name=task_name_ca,
        defaults={
            'interval': schedule,
            'task': 'users.tasks.check_issuing_ca_validity',
            'enabled': True
        }
    )

    if task_created_ca:
        logger.debug(f"Created new periodic task: {task_name_ca}")
    else:
        logger.debug(f"Updated existing periodic task: {task_name_ca}")

    task_name = 'Test task'
    periodic_task_ca, task_created_ca = PeriodicTask.objects.update_or_create(
        name=task_name,
        defaults={
            'interval': schedule,
            'task': 'users.tasks.test_task',
            'enabled': True
        }
    )

    if task_created_ca:
        logger.debug(f"Created new periodic task: {task_name_ca}")
    else:
        logger.debug(f"Updated existing periodic task: {task_name_ca}")
