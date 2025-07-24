from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [
        ('core', '0006_add_keystroke_model'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='email_verification_token',
            field=models.CharField(max_length=255, blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='email_verification_expiration',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='face_data',
            field=models.BinaryField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name='user',
            name='force_reenroll',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='two_factor_enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='failed_login_attempts',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='user',
            name='last_failed_login',
            field=models.DateTimeField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name='user',
            name='emergency_token_used',
            field=models.BooleanField(default=False),
        ),
    ]
