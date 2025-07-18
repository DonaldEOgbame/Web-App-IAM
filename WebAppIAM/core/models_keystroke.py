from django.db import models
from django.conf import settings

class KeystrokeDynamics(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='keystroke_dynamics')
    session_id = models.CharField(max_length=128, blank=True, null=True)
    event_data = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Keystroke data for {self.user.username} at {self.created_at}"
