from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings

class Migration(migrations.Migration):
    dependencies = [
        ('core', '0007_add_missing_user_fields'),
    ]

    operations = [
        migrations.CreateModel(
            name='DeviceFingerprint',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('device_id', models.CharField(max_length=64, unique=True)),
                ('device_name', models.CharField(max_length=100, blank=True, null=True)),
                ('browser', models.CharField(max_length=50, blank=True, null=True)),
                ('operating_system', models.CharField(max_length=50, blank=True, null=True)),
                ('device_type', models.CharField(default='Desktop', max_length=20)),
                ('user_agent', models.TextField()),
                ('first_seen', models.DateTimeField(auto_now_add=True)),
                ('last_seen', models.DateTimeField(auto_now=True)),
                ('is_trusted', models.BooleanField(default=False)),
                ('times_used', models.PositiveIntegerField(default=1)),
                ('last_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('last_location', models.CharField(max_length=100, blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='device_fingerprints', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-last_seen']},
        ),
        migrations.RemoveField(
            model_name='document',
            name='file',
        ),
        migrations.AddField(
            model_name='document',
            name='encrypted_file',
            field=models.BinaryField(default=b''),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='document',
            name='original_filename',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='document',
            name='file_type',
            field=models.CharField(default='', max_length=50),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='document',
            name='file_size',
            field=models.PositiveIntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='document',
            name='encryption_key',
            field=models.BinaryField(default=b''),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='document',
            name='deletion_reason',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='auditlog',
            name='affected_user',
            field=models.ForeignKey(null=True, blank=True, on_delete=models.deletion.SET_NULL, related_name='affected_audit_logs', to=settings.AUTH_USER_MODEL),
        ),
    ]
