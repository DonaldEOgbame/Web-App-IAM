import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'WebAppIAM.settings')
django.setup()

from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from .models import User, Document


class DocumentEditTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user(username="admin", password="pass", role="ADMIN")
        self.client.force_login(self.admin)
        self.doc = Document.objects.create(
            title="Doc",
            description="",
            access_level="PRIVATE",
            encrypted_file=b"a",
            original_filename="a.txt",
            file_type="text/plain",
            file_size=1,
            encryption_key=b"k",
            uploaded_by=self.admin,
        )

    def test_edit_creates_new_version(self):
        new_file = SimpleUploadedFile("b.txt", b"b", content_type="text/plain")
        with self.settings(ALLOWED_HOSTS=['testserver']):
            resp = self.client.post(
                reverse('core:document_edit', args=[self.doc.id]),
                {
                    'title': 'Doc',
                    'description': '',
                    'access_level': 'PRIVATE',
                    'department': '',
                    'file': new_file,
                },
            )
        self.assertEqual(resp.status_code, 302)
        new_doc = Document.objects.get(title="Doc", deleted=False)
        self.assertEqual(new_doc.version, self.doc.version + 1)
        self.assertTrue(Document.objects.filter(id=self.doc.id, deleted=True).exists())
