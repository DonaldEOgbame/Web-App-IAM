from django.test import TestCase
from django.urls import reverse
from .models import User, UserSession

class LogoutSessionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="u", password="p", is_active=True)
        self.client.force_login(self.user)
        session_key = self.client.session.session_key or ""
        self.session = UserSession.objects.create(
            user=self.user,
            session_key=session_key,
            ip_address="1.1.1.1",
            user_agent="agent"
        )

    def test_logout_sets_logout_time(self):
        with self.settings(ALLOWED_HOSTS=['testserver']):
            self.client.get(reverse("core:logout"))
        self.session.refresh_from_db()
        self.assertIsNotNone(self.session.logout_time)

class AdminLockTests(TestCase):
    def test_admin_cannot_lock_admin(self):
        admin1 = User.objects.create_user(username="a1", password="p", role="ADMIN", is_active=True)
        admin2 = User.objects.create_user(username="a2", password="p", role="ADMIN", is_active=True)
        self.client.force_login(admin1)
        self.client.post(reverse("core:admin_lock_user", args=[admin2.id]))
        admin2.refresh_from_db()
        self.assertTrue(admin2.is_active)

    def test_superuser_can_lock_admin(self):
        superuser = User.objects.create_superuser(username="sup", password="p", email="s@x.com")
        admin = User.objects.create_user(username="a", password="p", role="ADMIN", is_active=True)
        self.client.force_login(superuser)
        with self.settings(ALLOWED_HOSTS=['testserver']):
            self.client.post(reverse("core:admin_lock_user", args=[admin.id]))
        admin.refresh_from_db()
        self.assertFalse(admin.is_active)
