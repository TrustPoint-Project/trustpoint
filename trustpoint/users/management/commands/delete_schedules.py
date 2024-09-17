from django.core.management.base import BaseCommand
from users.scheduler import TaskScheduler

class Command(BaseCommand):
    help = 'Delete existing schedules'

    def handle(self, *args, **kwargs):
        scheduler = TaskScheduler()
        scheduler.delete_existing_schedules()
        self.stdout.write(self.style.SUCCESS('Successfully deleted and rescheduled tasks'))
