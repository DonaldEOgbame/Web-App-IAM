from django.core.management.base import BaseCommand
import logging
from core.face_api import check_face_api_status

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = "Check availability of the local DeepFace service"

    def handle(self, *args, **options):
        try:
            ok = check_face_api_status()
            if ok:
                self.stdout.write(self.style.SUCCESS("DeepFace operational"))
                return 0
            self.stderr.write(self.style.ERROR("DeepFace is not available"))
            return 1
        except Exception as e:
            logger.exception("Face service ping failed")
            self.stderr.write(self.style.ERROR(f"Face service check failed: {e}"))
            return 1
