# Generated manually to handle model changes

from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_userbehaviorprofile'),
    ]

    operations = [
        # Remove old enrollment fields that are no longer needed
        migrations.RemoveField(
            model_name='user',
            name='FACE_ENROLLED',
        ),
        migrations.RemoveField(
            model_name='user',
            name='FINGERPRINT_ENROLLED',
        ),
        # Remove old DocumentAccessLog fields
        migrations.RemoveField(
            model_name='documentaccesslog',
            name='fingerprint_status',
        ),
        migrations.RemoveField(
            model_name='documentaccesslog',
            name='was_blocked',
        ),
    ]
