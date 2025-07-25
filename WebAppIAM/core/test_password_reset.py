from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from unittest.mock import patch
import os
import django
from django.core.management import call_command

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'WebAppIAM.settings')
django.setup()
call_command('migrate', run_syncdb=True, verbosity=0)

from .views import password_reset_request

User = get_user_model()

class PasswordResetTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='foo', password='bar', email='foo@example.com')

    def test_unknown_email_shows_error(self):
        request = self.factory.post('/', {'email': 'unknown@example.com'})
        response = password_reset_request(request)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'User with this email does not exist.', response.content)

    @patch('core.views.send_mail')
    def test_valid_email_sends_reset(self, mock_send):
        request = self.factory.post('/', {'email': 'foo@example.com'}, HTTP_HOST='testserver')
        with self.settings(ALLOWED_HOSTS=['testserver']):
            response = password_reset_request(request)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Reset Email Sent', response.content)
        self.assertTrue(mock_send.called)
