# Generated by Django 5.2.4 on 2025-07-24 14:14

import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0008_update_document_and_device'),
    ]

    operations = [
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('read', models.BooleanField(default=False)),
                ('notification_type', models.CharField(choices=[('INFO', 'Information'), ('WARNING', 'Warning'), ('RISK', 'Security Risk'), ('EXPIRY', 'Document Expiry'), ('APPROVAL', 'Approval Required'), ('DEVICE', 'New Device Login'), ('LOCATION', 'Unusual Location')], default='INFO', max_length=20)),
                ('link', models.CharField(blank=True, max_length=256, null=True)),
                ('action_required', models.BooleanField(default=False)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('full_name', models.CharField(max_length=255)),
                ('department', models.CharField(choices=[('HR', 'Human Resources'), ('FINANCE', 'Finance'), ('IT', 'Information Technology'), ('SALES', 'Sales'), ('MARKETING', 'Marketing'), ('OPERATIONS', 'Operations'), ('LEGAL', 'Legal')], max_length=20)),
                ('position', models.CharField(max_length=100)),
                ('phone', models.CharField(blank=True, max_length=20, null=True)),
                ('profile_picture', models.ImageField(blank=True, null=True, upload_to='profile_pictures/')),
                ('profile_completed', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('show_risk_alerts', models.BooleanField(default=True)),
                ('show_face_match', models.BooleanField(default=False)),
                ('auto_logout', models.BooleanField(default=False)),
                ('receive_email_alerts', models.BooleanField(default=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='usernotification',
            name='user',
        ),
        migrations.RemoveField(
            model_name='userpreference',
            name='user',
        ),
        migrations.AlterModelOptions(
            name='document',
            options={'ordering': ['-created_at'], 'permissions': [('can_restore_document', 'Can restore deleted documents'), ('can_view_audit_log', 'Can view document access logs')]},
        ),
        migrations.AlterModelOptions(
            name='documentaccesslog',
            options={'ordering': ['-timestamp']},
        ),
        migrations.RemoveField(
            model_name='documentaccesslog',
            name='face_score',
        ),
        migrations.RemoveField(
            model_name='documentaccesslog',
            name='risk_score',
        ),
        migrations.AddField(
            model_name='documentaccesslog',
            name='access_type',
            field=models.CharField(choices=[('DOWNLOAD', 'Download'), ('PREVIEW', 'Preview'), ('SHARE', 'Share'), ('EDIT', 'Edit')], default='DOWNLOAD', max_length=10),
        ),
        migrations.AddField(
            model_name='documentaccesslog',
            name='device_info',
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name='documentaccesslog',
            name='location',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='documentaccesslog',
            name='reason',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='documentaccesslog',
            name='was_successful',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='riskpolicy',
            name='critical_risk_action',
            field=models.CharField(choices=[('ALLOW', 'Allow access'), ('CHALLENGE', 'Require additional verification'), ('DENY', 'Deny access'), ('NOTIFY', 'Allow but notify admin')], default='DENY', max_length=20),
        ),
        migrations.AddField(
            model_name='riskpolicy',
            name='lock_after_failed_attempts',
            field=models.PositiveIntegerField(default=5),
        ),
        migrations.AddField(
            model_name='riskpolicy',
            name='low_risk_action',
            field=models.CharField(choices=[('ALLOW', 'Allow access'), ('CHALLENGE', 'Require additional verification'), ('DENY', 'Deny access'), ('NOTIFY', 'Allow but notify admin')], default='ALLOW', max_length=20),
        ),
        migrations.AddField(
            model_name='riskpolicy',
            name='medium_risk_action',
            field=models.CharField(choices=[('ALLOW', 'Allow access'), ('CHALLENGE', 'Require additional verification'), ('DENY', 'Deny access'), ('NOTIFY', 'Allow but notify admin')], default='CHALLENGE', max_length=20),
        ),
        migrations.AddField(
            model_name='riskpolicy',
            name='require_reauth_for_documents',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='riskpolicy',
            name='session_timeout',
            field=models.PositiveIntegerField(default=30, help_text='Inactivity timeout in minutes'),
        ),
        migrations.AddField(
            model_name='usersession',
            name='is_mobile',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='usersession',
            name='location',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='webauthncredential',
            name='device_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='action',
            field=models.CharField(choices=[('USER_REGISTER', 'User Registration'), ('USER_ACTIVATE', 'User Activation'), ('LOGIN_ATTEMPT', 'Login Attempt'), ('LOGIN_SUCCESS', 'Successful Login'), ('LOGIN_FAIL', 'Failed Login'), ('FACE_ENROLL', 'Face Enrollment'), ('FACE_ENROLLED', 'Face Enrollment'), ('FINGERPRINT_ENROLL', 'Fingerprint Enrollment'), ('RISK_EVAL', 'Risk Evaluation'), ('ACCESS_GRANTED', 'Access Granted'), ('ACCESS_DENIED', 'Access Denied'), ('PASSWORD_CHANGE', 'Password Change'), ('PROFILE_UPDATE', 'Profile Update'), ('DOC_UPLOAD', 'Document Upload'), ('DOC_DOWNLOAD', 'Document Download'), ('DOC_DELETE', 'Document Deletion'), ('DOC_RESTORE', 'Document Restore'), ('DOCUMENT_CREATED', 'Document Created'), ('DOCUMENT_PURGE', 'Document Purged'), ('DOCUMENT_RESTORE', 'Document Restored'), ('POLICY_UPDATE', 'Policy Update'), ('ACCOUNT_LOCK', 'Account Locked'), ('ACCOUNT_UNLOCK', 'Account Unlocked'), ('FORCE_REENROLL', 'Forced Re-enrollment'), ('LOGOUT', 'User Logout'), ('EMAIL_CHANGE', 'Email Changed'), ('PASSWORD_RESET', 'Password Reset'), ('DEVICE_NEW', 'New Device Detected'), ('DEVICE_TRUST', 'Device Trusted'), ('DEVICE_REMOVE', 'Device Removed'), ('LOCATION_NEW', 'New Location Detected')], max_length=20),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='audit_logs', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='document',
            name='access_level',
            field=models.CharField(choices=[('PRIVATE', 'Private (Owner Only)'), ('DEPT', 'Department Access'), ('ORG', 'Organization Access'), ('PUBLIC', 'Public Access')], default='PRIVATE', max_length=15),
        ),
        migrations.AlterField(
            model_name='document',
            name='category',
            field=models.CharField(choices=[('GENERAL', 'General'), ('CONFIDENTIAL', 'Confidential'), ('RESTRICTED', 'Restricted'), ('SENSITIVE', 'Sensitive'), ('PUBLIC', 'Public')], default='GENERAL', max_length=15),
        ),
        migrations.AlterField(
            model_name='document',
            name='deleted',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='document',
            name='parent',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='versions', to='core.document'),
        ),
        migrations.AlterField(
            model_name='document',
            name='uploaded_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='uploaded_documents', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='document',
            name='version',
            field=models.PositiveIntegerField(default=1),
        ),
        migrations.AlterField(
            model_name='documentaccesslog',
            name='session',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='document_accesses', to='core.usersession'),
        ),
        migrations.AlterField(
            model_name='documentaccesslog',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='document_accesses', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='riskpolicy',
            name='behavior_anomaly_threshold',
            field=models.FloatField(default=0.6, validators=[django.core.validators.MinValueValidator(0.0), django.core.validators.MaxValueValidator(1.0)]),
        ),
        migrations.AlterField(
            model_name='riskpolicy',
            name='face_match_threshold',
            field=models.FloatField(default=0.75, validators=[django.core.validators.MinValueValidator(0.0), django.core.validators.MaxValueValidator(1.0)]),
        ),
        migrations.AlterField(
            model_name='riskpolicy',
            name='high_risk_action',
            field=models.CharField(choices=[('ALLOW', 'Allow access'), ('CHALLENGE', 'Require additional verification'), ('DENY', 'Deny access'), ('NOTIFY', 'Allow but notify admin')], default='DENY', max_length=20),
        ),
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('STAFF', 'Staff'), ('ADMIN', 'Administrator')], default='STAFF', max_length=10),
        ),
        migrations.AlterField(
            model_name='usersession',
            name='behavior_anomaly_score',
            field=models.FloatField(blank=True, null=True, validators=[django.core.validators.MinValueValidator(0.0), django.core.validators.MaxValueValidator(1.0)]),
        ),
        migrations.AlterField(
            model_name='usersession',
            name='risk_level',
            field=models.CharField(choices=[('LOW', 'Low Risk'), ('MEDIUM', 'Medium Risk'), ('HIGH', 'High Risk'), ('CRITICAL', 'Critical Risk')], default='LOW', max_length=10),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['action', 'timestamp'], name='core_auditl_action_096de0_idx'),
        ),
        migrations.AddIndex(
            model_name='devicefingerprint',
            index=models.Index(fields=['user', 'is_trusted'], name='core_device_user_id_b9a8df_idx'),
        ),
        migrations.AddIndex(
            model_name='devicefingerprint',
            index=models.Index(fields=['device_id'], name='core_device_device__3a827e_idx'),
        ),
        migrations.AddIndex(
            model_name='document',
            index=models.Index(fields=['access_level', 'category'], name='core_docume_access__74d14c_idx'),
        ),
        migrations.AddIndex(
            model_name='document',
            index=models.Index(fields=['department'], name='core_docume_departm_94bc16_idx'),
        ),
        migrations.AddIndex(
            model_name='documentaccesslog',
            index=models.Index(fields=['document', 'was_successful'], name='core_docume_documen_462091_idx'),
        ),
        migrations.AddIndex(
            model_name='documentaccesslog',
            index=models.Index(fields=['user', 'access_type'], name='core_docume_user_id_42b7cf_idx'),
        ),
        migrations.AddIndex(
            model_name='usersession',
            index=models.Index(fields=['user', 'risk_level'], name='core_userse_user_id_a8ed15_idx'),
        ),
        migrations.AddIndex(
            model_name='usersession',
            index=models.Index(fields=['login_time'], name='core_userse_login_t_ede1cb_idx'),
        ),
        migrations.AddField(
            model_name='notification',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notifications', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL),
        ),
        migrations.DeleteModel(
            name='UserNotification',
        ),
        migrations.DeleteModel(
            name='UserPreference',
        ),
        migrations.AddIndex(
            model_name='notification',
            index=models.Index(fields=['user', 'read'], name='core_notifi_user_id_4a178e_idx'),
        ),
    ]
