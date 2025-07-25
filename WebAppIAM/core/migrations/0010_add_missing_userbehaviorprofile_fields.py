from django.db import migrations, connection


def add_missing_columns(apps, schema_editor):
    cursor = connection.cursor()
    cursor.execute("PRAGMA table_info(core_userbehaviorprofile);")
    existing = {row[1] for row in cursor.fetchall()}
    if 'login_time_variance' not in existing:
        cursor.execute("ALTER TABLE core_userbehaviorprofile ADD COLUMN login_time_variance INTEGER DEFAULT 60;")
    if 'typical_ip_range' not in existing:
        cursor.execute("ALTER TABLE core_userbehaviorprofile ADD COLUMN typical_ip_range VARCHAR(50);")
    if 'keyboard_pattern' not in existing:
        cursor.execute("ALTER TABLE core_userbehaviorprofile ADD COLUMN keyboard_pattern TEXT;")
    if 'mouse_movement_pattern' not in existing:
        cursor.execute("ALTER TABLE core_userbehaviorprofile ADD COLUMN mouse_movement_pattern TEXT;")

class Migration(migrations.Migration):
    dependencies = [
        ('core', '0009_notification_userprofile_and_more'),
    ]

    operations = [
        migrations.RunPython(add_missing_columns, migrations.RunPython.noop),
    ]
