"""
Management command: create_investigator

Creates a default investigator account if none exists.
Usage: python manage.py create_investigator
       python manage.py create_investigator --username analyst --password secret123
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User


class Command(BaseCommand):
    help = 'Create a default investigator account (admin-controlled, no self-registration)'

    def add_arguments(self, parser):
        parser.add_argument('--username', default='investigator')
        parser.add_argument('--password', default='forensic2024!')
        parser.add_argument('--email', default='investigator@forensictool.local')

    def handle(self, *args, **options):
        username = options['username']
        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(f'User "{username}" already exists.'))
            return
        User.objects.create_superuser(
            username=username,
            email=options['email'],
            password=options['password'],
        )
        self.stdout.write(self.style.SUCCESS(
            f'Investigator account created: username="{username}" password="{options["password"]}"'
        ))
