# apps/accounts/models.py
import uuid
from datetime import timedelta
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.hashers import make_password
from django.utils import timezone

class UserManager(BaseUserManager):
    def create_user(self, email, name, password=None, **extra_fields):
        if not email:
            raise ValueError('يجب إدخال البريد الإلكتروني')
        if not name:
            raise ValueError('يجب إدخال الاسم')
        
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        return self.create_user(email, name, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255, unique=True)
    profile_image = models.ImageField(
        upload_to='profile_images/', 
        null=True, 
        blank=True
    )
    
    scanned_links = models.IntegerField(default=0)
    detected_threats = models.IntegerField(default=0)
    accuracy_rate = models.FloatField(default=0.0)
    
    is_email_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']
    
    def __str__(self):
        return self.email

def get_otp_expiry():
    return timezone.now() + timedelta(minutes=5)

class EmailVerification(models.Model):
    PURPOSE_CHOICES = [
        ('register', 'Register'),
        ('reset', 'Password Reset'),
    ]
    
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255, blank=True)
    password = models.CharField(max_length=128, blank=True)
    otp = models.CharField(max_length=6)
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, default='register')
    
    # Security fields
    otp_attempts = models.IntegerField(default=0)
    last_request_at = models.DateTimeField(auto_now_add=True)
    request_count = models.IntegerField(default=1) 
    lockout_until = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=get_otp_expiry)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def __str__(self):
        return f"Verification ({self.purpose}) for {self.email}"

class IPAttempt(models.Model):
    ip_address = models.GenericIPAddressField()
    count = models.IntegerField(default=0)
    last_attempt_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.ip_address}: {self.count} attempts"