from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='emergency_token_hash',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='emergency_token_expiry',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterModelOptions(
            name='user',
            options={'permissions': [
                ('can_force_reenroll', 'Can force biometric re-enrollment'), 
                ('can_lock_account', 'Can lock/unlock user accounts'), 
                ('bypass_biometrics', 'Can bypass biometric authentication'),
                ('manage_emergency_access', 'Can manage emergency access protocol'),
            ]},
        ),
    ]
