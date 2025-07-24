from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_add_emergency_token_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name="userbehaviorprofile",
            name="login_time_variance",
            field=models.IntegerField(default=60, help_text="Variance in minutes"),
        ),
        migrations.AddField(
            model_name="userbehaviorprofile",
            name="typical_ip_range",
            field=models.CharField(max_length=50, blank=True, null=True),
        ),
        migrations.AddField(
            model_name="userbehaviorprofile",
            name="keyboard_pattern",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="userbehaviorprofile",
            name="mouse_movement_pattern",
            field=models.TextField(blank=True, null=True),
        ),
    ]
