from django.core.management.base import BaseCommand

from home.models import NotificationModel


class Command(BaseCommand):
    help = 'Deletes all existing notifications'

    def handle(self, *args, **options):
        confirm = input('Are you sure you want to delete all notifications? Type "yes" to confirm: ')
        if confirm.lower() == 'yes':
            count, _ = NotificationModel.objects.all().delete()
            self.stdout.write(self.style.SUCCESS(f'Deleted {count} notifications.'))
        else:
            self.stdout.write('Deletion cancelled.')
