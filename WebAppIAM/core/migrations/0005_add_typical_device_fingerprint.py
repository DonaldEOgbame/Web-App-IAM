# Generated by Django 5.2.4 on 2025-07-23 19:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0004_remove_old_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="userbehaviorprofile",
            name="typical_device_fingerprint",
            field=models.CharField(max_length=255, blank=True, null=True),
        )
    ]
