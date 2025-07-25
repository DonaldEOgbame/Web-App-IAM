from django.core.management.base import BaseCommand
from core.face_api import get_face_client
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = "Check connectivity to the Azure Face API"

    def handle(self, *args, **options):
        try:
            client = get_face_client()
            next(client.person_group.list(top=1), None)
            self.stdout.write(self.style.SUCCESS("Face API reachable"))
        except Exception as e:
            logger.exception("Face API ping failed")
            self.stderr.write(self.style.ERROR(f"Face API check failed: {e}"))
            return 1
