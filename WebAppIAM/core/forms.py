from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from .models import User, RiskPolicy, Document

class RegistrationForm(UserCreationForm):
    role = forms.ChoiceField(choices=[('USER', 'User'), ('ADMIN', 'Admin')], initial='USER')
    class Meta:
        model = User
        fields = ('username', 'role', 'password1', 'password2')

class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)

class FaceEnrollForm(forms.Form):
    face_image = forms.ImageField(required=True)

class FingerprintReRegisterForm(forms.Form):
    # Placeholder for WebAuthn JS integration
    pass

class RiskPolicyForm(forms.ModelForm):
    class Meta:
        model = RiskPolicy
        fields = ['name', 'description', 'face_match_threshold', 'behavior_anomaly_threshold', 'fingerprint_required', 'high_risk_action', 'is_active']

class ReportSubmissionForm(forms.Form):
    report = forms.CharField(widget=forms.Textarea, required=True)

class CustomPasswordChangeForm(PasswordChangeForm):
    pass

class DocumentUploadForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['title', 'file', 'description', 'access_level', 'category', 'department', 'expiry_date']
        widgets = {
            'expiry_date': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        }
