# Generated by Django 5.2.4 on 2025-08-01 23:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0015_usersession_device_anomaly_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="email",
            field=models.EmailField(blank=True, max_length=254, unique=True),
        ),
    ]
