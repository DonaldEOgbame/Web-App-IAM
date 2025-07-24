from django.test import TestCase, RequestFactory
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from unittest.mock import patch, MagicMock
import requests
from django.conf import settings

from .emergency import EmergencyAccessProtocol
from .face_api import check_face_api_status, verify_face, FaceAPIError
from .csrf import ensure_csrf
from .security_middleware import (
    ContentSecurityPolicyMiddleware,
    StrictTransportSecurityMiddleware,
    APICSRFProtectionMiddleware,
)
from .risk_engine import calculate_risk_score, analyze_behavior_anomaly
from .health import health_check

User = get_user_model()

class EmergencyProtocolTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="admin", password="x", email="a@example.com", role="ADMIN", is_active=True)

    @patch("core.emergency.send_mail")
    @patch("django.core.cache.cache")
    def test_activate_and_deactivate(self, mock_cache, mock_send):
        settings.EMERGENCY_ACCESS_MODE = False
        EmergencyAccessProtocol.activate_emergency_mode(self.user, "testing")
        self.assertTrue(settings.EMERGENCY_ACCESS_MODE)
        EmergencyAccessProtocol.deactivate_emergency_mode(self.user)
        self.assertFalse(settings.EMERGENCY_ACCESS_MODE)
        self.assertTrue(mock_send.called)
        self.assertTrue(mock_cache.set.called)

    def test_token_generation_and_verification(self):
        token = EmergencyAccessProtocol.generate_emergency_token(self.user)
        self.assertIsNotNone(self.user.emergency_token_hash)
        self.assertTrue(EmergencyAccessProtocol.verify_emergency_token(self.user, token))
        self.assertTrue(self.user.emergency_token_used)

class CSRFDecoratorTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_get_adds_token(self):
        @ensure_csrf
        def view(request):
            return JsonResponse({"ok": True})
        request = self.factory.get("/")
        response = view(request)
        self.assertIn("X-CSRFToken", response)

    def test_post_validates_token(self):
        @ensure_csrf
        def view(request):
            return JsonResponse({"ok": True})
        request = self.factory.post("/")
        request.session = {"csrftoken": "abc"}
        request.META["HTTP_X_CSRFTOKEN"] = "abc"
        response = view(request)
        self.assertEqual(response.status_code, 200)

class MiddlewareTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_csp_and_hsts(self):
        def get_response(request):
            return JsonResponse({})
        settings.DEBUG = False
        request = self.factory.get("/")
        resp = ContentSecurityPolicyMiddleware(get_response)(request)
        resp = StrictTransportSecurityMiddleware(lambda r: resp)(request)
        self.assertIn("Content-Security-Policy", resp)
        self.assertIn("Strict-Transport-Security", resp)

    def test_api_csrf_passthrough(self):
        def get_response(request):
            return JsonResponse({"ok": True})
        request = self.factory.post("/api/test")
        resp = APICSRFProtectionMiddleware(get_response)(request)
        self.assertEqual(resp.status_code, 200)

class FaceAPITests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="u1", password="p")

    @patch("requests.get", side_effect=requests.RequestException("fail"))
    def test_check_face_api_status_unavailable(self, mock_get):
        self.assertFalse(check_face_api_status())

    def test_verify_face_disabled(self):
        with self.settings(FACE_API_ENABLED=False):
            result = verify_face(self.user, MagicMock(), use_fallback=True)
            self.assertTrue(result["fallback"])
            with self.assertRaises(FaceAPIError):
                verify_face(self.user, MagicMock(), use_fallback=False)

    def test_verify_face_no_enrollment(self):
        with self.settings(FACE_API_ENABLED=True):
            with patch("core.face_api.check_face_api_status", return_value=True):
                result = verify_face(self.user, MagicMock(), use_fallback=True)
                self.assertEqual(result["confidence"], 0.3)

class RiskEngineTests(TestCase):
    def test_calculate_and_analyze(self):
        class Dummy:
            def predict(self, X):
                return [0.9]
        class Behave:
            def predict(self, X):
                return [0.2]
        with patch("core.risk_engine.load_models", return_value=(Dummy(), Behave())), \
             patch("core.risk_engine.risk_model", Dummy(), create=True), \
             patch("core.risk_engine.behavior_model", Behave(), create=True):
            result = calculate_risk_score(1, 1, 0)
            self.assertEqual(result, 0.9)
            session = type("S", (), {"time_anomaly":0, "device_anomaly":0, "location_anomaly":0})()
            anomaly = analyze_behavior_anomaly(session)
            self.assertEqual(anomaly, 0.2)

class HealthCheckTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_health_check(self):
        with patch("core.health.check_services", return_value={"status": "operational"}):
            resp = health_check(self.factory.get("/"))
            self.assertEqual(resp.status_code, 200)
        with patch("core.health.check_services", return_value={"status": "degraded"}):
            resp = health_check(self.factory.get("/"))
            self.assertEqual(resp.status_code, 503)
