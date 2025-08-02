from django.core.management.base import BaseCommand
from core.models import UserProfile

class Command(BaseCommand):
    help = 'Set all users to level 1 access control.'

    def handle(self, *args, **options):
        updated = UserProfile.objects.update(access_level=1)
        self.stdout.write(self.style.SUCCESS(f'Successfully updated {updated} user profiles to level 1 access control.'))
