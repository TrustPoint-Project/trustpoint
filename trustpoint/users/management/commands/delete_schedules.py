from django.core.management.base import BaseCommand
from users.scheduler import delete_existing_schedules

class Command(BaseCommand):
    help = 'Delete existing schedules'

    def handle(self, *args, **kwargs):
        delete_existing_schedules()
        self.stdout.write(self.style.SUCCESS('Successfully deleted and rescheduled tasks'))
