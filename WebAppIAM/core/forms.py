from django import forms
from django.contrib.auth.forms import PasswordChangeForm
from .models import User, RiskPolicy, Document, UserProfile

class RegistrationForm(forms.ModelForm):
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )
    password2 = forms.CharField(
        label='Password confirmation',
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )
    
    class Meta:
        model = User
        fields = ['username', 'email']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }
        
    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        return password2

class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'})
    )

class FaceEnrollForm(forms.Form):
    face_image = forms.ImageField(
        label='Upload a clear face image',
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': 'image/*'})
    )

class FingerprintReRegisterForm(forms.Form):
    confirm = forms.BooleanField(
        required=True,
        label='I understand that this will delete my existing fingerprint credentials',
    )

class RiskPolicyForm(forms.ModelForm):
    class Meta:
        model = RiskPolicy
        exclude = ['created_at', 'updated_at']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'face_match_threshold': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'min': '0', 'max': '1'}),
            'behavior_anomaly_threshold': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'min': '0', 'max': '1'}),
            'session_timeout': forms.NumberInput(attrs={'class': 'form-control', 'min': '1'}),
            'lock_after_failed_attempts': forms.NumberInput(attrs={'class': 'form-control', 'min': '1'}),
        }

class ReportSubmissionForm(forms.Form):
    report = forms.CharField(widget=forms.Textarea, required=True)

class CustomPasswordChangeForm(PasswordChangeForm):
    pass

class DocumentUploadForm(forms.ModelForm):
    file = forms.FileField(label='File to upload')
    # Present predefined department choices instead of a free text field
    department = forms.ChoiceField(
        choices=UserProfile.DEPT_CHOICES,
        required=False
    )
    
    class Meta:
        model = Document
        fields = ['title', 'description', 'access_level', 'category', 'department', 'expiry_date']
        widgets = {
            'expiry_date': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        }
        
    def save(self, commit=True):
        # Don't save the file directly, it will be encrypted in the view
        # This is just for the form validation
        return super().save(commit=commit)

class ProfileCompletionForm(forms.ModelForm):
    first_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First Name'})
    )
    last_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last Name'})
    )
    
    class Meta:
        model = UserProfile
        fields = ['department', 'position', 'phone', 'profile_picture']
        widgets = {
            'position': forms.TextInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control', 'placeholder': '+1 (555) 555-5555'}),
        }

class ProfileUpdateForm(forms.ModelForm):
    first_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First Name'})
    )
    last_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last Name'})
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    
    class Meta:
        model = UserProfile
        fields = ['department', 'position', 'phone', 'profile_picture', 
                  'show_risk_alerts', 'show_face_match', 'auto_logout', 'receive_email_alerts']
        widgets = {
            'position': forms.TextInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
        }

class PasswordResetForm(forms.Form):
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your email'})
    )

    def clean_email(self):
        email = self.cleaned_data['email']
        if not User.objects.filter(email=email).exists():
            raise forms.ValidationError("User with this email does not exist.")
        return email

class PasswordResetConfirmForm(forms.Form):
    password1 = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter new password'})
    )
    password2 = forms.CharField(
        label="Confirm password",
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm new password'})
    )
    
    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        
        return cleaned_data
