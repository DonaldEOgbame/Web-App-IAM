from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_add_emergency_token_fields'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserBehaviorProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('typical_login_time', models.TimeField(blank=True, null=True)),
                ('login_time_variance', models.IntegerField(default=60, help_text='Variance in minutes')),
                ('typical_device', models.CharField(blank=True, max_length=255, null=True)),
                ('typical_location', models.CharField(blank=True, max_length=255, null=True)),
                ('typical_ip_range', models.CharField(blank=True, max_length=50, null=True)),
                ('keyboard_pattern', models.TextField(blank=True, null=True)),
                ('mouse_movement_pattern', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='behavior_profile', to='core.user')),
            ],
        ),
    ]
