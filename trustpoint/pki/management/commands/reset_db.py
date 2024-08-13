"""Django management command for removing all migrations, db, creates migrations and superuser."""


from __future__ import annotations

from pathlib import Path
import os

from django.core.management import BaseCommand, call_command
from django.contrib.auth.models import User
from django.core.management.base import CommandParser


class Command(BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Removes all migrations, deletes db and runs makemigrations and migrate afterwards.'

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument('args', nargs='*', type=str)

    def handle(self, *args, **options) -> None:
        # Explicit user confirmation for deleting the database
        if 'y' not in args:
            print('This will delete the database and all migrations.')
            if input('Are you sure you want to continue? (y/n): ').lower() != 'y':
                print('Aborted.')
                return

        file_path = Path(__file__).parent.parent.parent.parent.resolve()
        for root, dirs, files in os.walk(file_path):
            if 'migrations' in root:
                for file in files:
                    if file.endswith('.py') and file != '__init__.py' or file.endswith('.pyc'):
                        os.remove(os.path.join(root, file))

        # Remove the SQLite database file
        db_path = file_path / 'db.sqlite3'
        if db_path.exists():
            os.remove(db_path)

        print('Making migrations...')
        call_command('makemigrations')
        print('Migrating db...')
        call_command('migrate')

        print('Creating superuser...')
        call_command('createsuperuser', interactive=False, username='admin', email='')
        user = User.objects.get(username='admin')
        user.set_password('testing321')
        user.save()

        print('\nSuperuser: admin')
        print('Password: testing321')

        print('\nDONE\n')