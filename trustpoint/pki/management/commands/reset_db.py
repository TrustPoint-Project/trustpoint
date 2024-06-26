"""Django management command for removing all migrations, db, creates migrations and superuser."""


from __future__ import annotations

from pathlib import Path
import subprocess

from django.core.management import BaseCommand, call_command
from django.contrib.auth.models import User


class Command(BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Removes all migrations, deletes db and runs makemigrations and migrate afterwards.'

    def handle(self, *args, **kwargs) -> None:
        file_path = Path(__file__).parent.parent.parent.parent.resolve()
        cmd1 = f'cd {file_path} && find . -path "*/migrations/*.py" -not -name "__init__.py" -delete'
        cmd2 = f'cd {file_path} && find . -path "*/migrations/*.pyc"  -delete'
        cmd3 = f'rm -f {file_path}/db.sqlite3'

        print('Removing migrations...')
        subprocess.run(cmd1, shell=True)
        subprocess.run(cmd2, shell=True)
        print('Removing db...')
        subprocess.run(cmd3, shell=True)

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