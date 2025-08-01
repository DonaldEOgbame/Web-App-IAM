from django.test import TestCase, RequestFactory, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from django.core.cache import cache
from django.urls import reverse

from .models import (
    User,
    Document,
    UserProfile,
    DeviceFingerprint,
    UserBehaviorProfile,
    WebAuthnCredential,
    UserSession,
)
from .forms import RegistrationForm, DocumentUploadForm
from .views import encrypt_file, decrypt_file, rate_limit, get_fernet_key
from . import risk_engine


class ModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="tester", password="pass", email="tester@example.com")

    def _create_document(self, deleted=False):
        return Document.objects.create(
            title="Test Doc",
            description="",
            access_level="PRIVATE",
            encrypted_file=b"data",
            original_filename="doc.txt",
            file_type="text/plain",
            file_size=100,
            encryption_key=b"key",
            uploaded_by=self.user,
            deleted=deleted,
        )

    def test_document_creation(self):
        doc = self._create_document()
        self.assertEqual(doc.access_level, "PRIVATE")
        self.assertFalse(doc.deleted)

    def test_device_fingerprint_usage(self):
        fp = DeviceFingerprint.objects.create(
            user=self.user,
            device_id="abc",
            browser="Chrome",
            operating_system="Linux",
            user_agent="agent",
        )
        initial = fp.times_used
        fp.update_usage(ip_address="1.1.1.1", location="US")
        fp.refresh_from_db()
        self.assertEqual(fp.times_used, initial + 1)
        self.assertEqual(fp.last_ip, "1.1.1.1")
        self.assertEqual(fp.last_location, "US")

        fp.mark_as_trusted()
        fp.refresh_from_db()
        self.assertTrue(fp.is_trusted)

    def test_device_fingerprint_unique_per_user(self):
        """Devices with the same fingerprint can be associated with different users"""
        user2 = User.objects.create_user(username="tester2", password="pass", email="tester2@example.com")

        DeviceFingerprint.objects.create(
            user=self.user,
            device_id="dup",
            browser="Chrome",
            operating_system="Linux",
            user_agent="agent",
        )
        DeviceFingerprint.objects.create(
            user=user2,
            device_id="dup",
            browser="Chrome",
            operating_system="Linux",
            user_agent="agent",
        )

        count = DeviceFingerprint.objects.filter(device_id="dup").count()
        self.assertEqual(count, 2)

    def test_behavior_profile_anomaly_checks(self):
        profile = UserBehaviorProfile.objects.create(
            user=self.user,
            typical_login_time=timezone.now().time(),
            typical_device="Laptop",
            typical_location="Home",
        )

        # Same values => low anomaly
        self.assertEqual(profile.check_time_anomaly(profile.typical_login_time), 0)
        self.assertEqual(profile.check_location_anomaly("Home"), 0)
        self.assertEqual(profile.check_device_anomaly("Laptop"), 0)

        # Different values => anomaly > 0
        late_time = (timezone.now() + timezone.timedelta(hours=5)).time()
        self.assertGreater(profile.check_time_anomaly(late_time), 0)
        self.assertEqual(profile.check_location_anomaly("Office"), 1)
        self.assertEqual(profile.check_device_anomaly("Phone"), 0.8)


class FormTests(TestCase):
    def test_registration_form_password_mismatch(self):
        form = RegistrationForm(
            {
                "username": "user",
                "email": "user@example.com",
                "password1": "abc",
                "password2": "def",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("password2", form.errors)

    def test_document_upload_form_valid(self):
        file_data = SimpleUploadedFile("file.txt", b"data", content_type="text/plain")
        form = DocumentUploadForm(
            {
                "title": "Doc",
                "access_level": "PRIVATE",
                "required_access_level": 1,
            },
            {"file": file_data},
        )
        self.assertTrue(form.is_valid())


class UtilityTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_encrypt_decrypt_roundtrip(self):
        data = b"hello"
        encrypted = encrypt_file(data)
        decrypted = decrypt_file(encrypted)
        self.assertEqual(decrypted, data)

    def test_rate_limit(self):
        request = self.factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        cache.clear()
        for _ in range(5):
            self.assertTrue(rate_limit(request, "test", limit=5, window=60))
        self.assertFalse(rate_limit(request, "test", limit=5, window=60))


class RiskEngineTests(TestCase):
    def test_load_models_raises_runtime_error(self):
        risk_engine.risk_model = None
        risk_engine.behavior_model = None
        # Simulate models previously attempted to load
        risk_engine._loaded = True
        with self.assertRaises(RuntimeError):
            risk_engine.load_models()


class DeviceViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user(
            username="admin",
            password="pass",
            email="admin@example.com",
            role="ADMIN",
            is_active=True,
        )
        self.staff = User.objects.create_user(
            username="staff",
            password="pass",
            email="staff@example.com",
            role="STAFF",
            is_active=True,
        )
        self.admin_fp = DeviceFingerprint.objects.create(
            user=self.admin,
            device_id="admin_dev",
            browser="Chrome",
            operating_system="Linux",
            user_agent="agent",
        )
        self.staff_fp = DeviceFingerprint.objects.create(
            user=self.staff,
            device_id="staff_dev",
            browser="Chrome",
            operating_system="Linux",
            user_agent="agent",
        )

    def test_staff_only_sees_own_devices(self):
        self.client.force_login(self.staff)
        response = self.client.get(reverse("core:manage_devices"))
        devices = list(response.context["devices"])
        self.assertEqual(devices, [self.staff_fp])

    def test_admin_only_sees_own_devices(self):
        self.client.force_login(self.admin)
        response = self.client.get(reverse("core:manage_devices"))
        devices = list(response.context["devices"])
        self.assertEqual(devices, [self.admin_fp])


class AccessLevelTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user(
            username="admin2",
            password="pass",
            email="admin2@example.com",
            role="ADMIN",
        )
        self.level1 = User.objects.create_user(
            username="level1",
            password="pass",
            email="level1@example.com",
            role="STAFF",
        )
        self.level3 = User.objects.create_user(
            username="level3",
            password="pass",
            email="level3@example.com",
            role="STAFF",
        )
        UserProfile.objects.create(user=self.admin, department="IT", position="Admin", access_level=3)
        UserProfile.objects.create(user=self.level1, department="IT", position="Staff", access_level=1)
        UserProfile.objects.create(user=self.level3, department="IT", position="Staff", access_level=3)

        key = get_fernet_key(self.admin)
        self.doc_l1 = Document.objects.create(
            title="Doc L1",
            description="",
            access_level="DEPT",
            required_access_level=1,
            department="IT",
            encrypted_file=encrypt_file(b"data1", self.admin),
            original_filename="l1.txt",
            file_type="text/plain",
            file_size=10,
            encryption_key=key,
            uploaded_by=self.admin,
        )
        self.doc_l3 = Document.objects.create(
            title="Doc L3",
            description="",
            access_level="DEPT",
            required_access_level=3,
            department="IT",
            encrypted_file=encrypt_file(b"data3", self.admin),
            original_filename="l3.txt",
            file_type="text/plain",
            file_size=10,
            encryption_key=key,
            uploaded_by=self.admin,
        )

    def test_document_list_filters_by_access_level(self):
        self.client.force_login(self.level1)
        response = self.client.get(reverse("core:document_list"))
        self.assertContains(response, "Doc L1")
        self.assertContains(response, "Doc L3")

        self.client.force_login(self.level3)
        response = self.client.get(reverse("core:document_list"))
        self.assertNotContains(response, "Doc L1")
        self.assertContains(response, "Doc L3")

    def test_document_download_requires_access_level(self):
        self.client.force_login(self.level3)
        resp = self.client.get(reverse("core:document_download", args=[self.doc_l1.id]))
        self.assertEqual(resp.status_code, 403)

        self.client.force_login(self.level1)
        resp = self.client.get(reverse("core:document_download", args=[self.doc_l1.id]))
        self.assertEqual(resp.status_code, 200)

    def test_admin_can_update_access_level(self):
        self.client.force_login(self.admin)
        self.client.post(reverse("core:admin_set_access_level", args=[self.level1.id, 3]))
        self.level1.profile.refresh_from_db()
        self.assertEqual(self.level1.profile.access_level, 3)


