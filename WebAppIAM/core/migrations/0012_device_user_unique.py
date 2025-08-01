# Generated by Django 5.2.4 on 2025-07-29 09:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0011_notification_metadata"),
    ]

    operations = [
        migrations.AlterField(
            model_name="devicefingerprint",
            name="device_id",
            field=models.CharField(max_length=64),
        ),
        migrations.AlterUniqueTogether(
            name="devicefingerprint",
            unique_together={("user", "device_id")},
        ),
    ]
