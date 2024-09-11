from users.tasks import check_certificate_validity, check_issuing_ca_validity, test_task
from django.core.management import BaseCommand


class Command(BaseCommand):
    """Django management command for testing the Celery worker with notifications."""

    def handle(self, *args, **kwargs) -> None:
        self.stdout.write(self.style.SUCCESS('Triggering certificate validity check...'))
        check_certificate_validity.delay()

        self.stdout.write(self.style.SUCCESS('Triggering issuing CA validity check...'))
        check_issuing_ca_validity.delay()

        self.stdout.write(self.style.SUCCESS('Triggering test task...'))
        test_task()

        self.stdout.write(self.style.SUCCESS('Tasks have been triggered.'))