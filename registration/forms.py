from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from chat.models import UserProfile
from hcaptcha.fields import hCaptchaField
import re
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError


class SignUpForm(forms.Form):
    username = forms.CharField(min_length=5, max_length=20,
                               error_messages={
                                   'required': 'Username is required.',
                                   'min_length': 'Username must be at least 5 characters.',
                                   'max_length': 'Username cannot exceed 20 characters.'
                               })
    name = forms.CharField(max_length=25, label="Name")
    email = forms.EmailField(label="Email")
    password1 = forms.CharField(min_length=8, max_length=20, label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label="Confirm Password", widget=forms.PasswordInput)
    # hcaptcha = hCaptchaField()

    def clean_password1(self):
        password = self.cleaned_data.get("password1")
        # VÃ©rifie qu'il n'y a que lettres et chiffres
        if not re.fullmatch(r'(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,20}', password):
            raise forms.ValidationError(
                "Password must be 8-20 characters long, contain only letters and numbers, and no spaces or special characters."
            )

            # Ensuite on applique les validateurs Django
        try:
            validate_password(password)
        except ValidationError as e:
            raise forms.ValidationError(e.messages)
        return password

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords do not match!")

        return cleaned_data

    def save(self, commit=True):
        user = User.objects.create_user(
            self.cleaned_data['username'],
            self.cleaned_data['email'],
            self.cleaned_data['password1']
        )
        return user


class CustomSignupForm(forms.Form):
    hcaptcha = hCaptchaField()