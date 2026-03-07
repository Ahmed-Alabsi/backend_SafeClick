# apps/scans/models.py
from django.db import models
from django.conf import settings
import uuid

class Scan(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scans',
        null=True,
        blank=True
    )
    
    url = models.URLField(max_length=2000)
    url_hash = models.CharField(max_length=64, db_index=True, null=True, blank=True)
    domain = models.CharField(max_length=255, db_index=True, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    result = models.CharField(max_length=50, null=True, blank=True) # equivalent to safe text
    safe = models.BooleanField(null=True) # keeping for backward compatibility
    risk_score = models.IntegerField(default=0) # maps to score
    score = models.IntegerField(default=0) # keeping for backward compatibility
    source = models.CharField(max_length=100, default='system')
    
    details = models.JSONField(default=list)
    threats_found = models.JSONField(default=list)
    threats_count = models.IntegerField(default=0)
    
    response_time = models.FloatField(default=0)
    server_info = models.CharField(max_length=255, null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    timestamp = models.DateTimeField(auto_now_add=True) # keeping for backward compatibility
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'فحص'
        verbose_name_plural = 'الفحوصات'
        indexes = [
            models.Index(fields=["url_hash"]),
            models.Index(fields=["domain"]),
            models.Index(fields=["created_at"]),
        ]
    
    def __str__(self):
        status = 'آمن' if self.safe == True else 'خطير' if self.safe == False else 'مشبوه'
        return f"{self.url[:50]} - {status} ({self.risk_score}%)"

class Link(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    url_hash = models.CharField(max_length=64, unique=True)
    domain = models.CharField(max_length=255, db_index=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    total_scans = models.IntegerField(default=0)
    last_result = models.CharField(max_length=50, null=True, blank=True)
    threat_score = models.IntegerField(default=0)
    
    class Meta:
        verbose_name = 'رابط'
        verbose_name_plural = 'الروابط'
    
    def __str__(self):
        return f"{self.domain} - Scans: {self.total_scans}"

class TrainingDataset(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    url = models.URLField(max_length=2000)
    label = models.CharField(max_length=50) # safe, phishing, malicious
    source = models.CharField(max_length=100, default='system')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'بيانات التدريب'
        verbose_name_plural = 'بيانات التدريب'
    
    def __str__(self):
        return f"{self.url[:50]} - {self.label}"
    
class Blacklist(models.Model):
    """قائمة الروابط المحظورة"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    link = models.URLField(max_length=2000)
    domain = models.CharField(max_length=255)
    threat_type = models.CharField(max_length=100)
    severity = models.IntegerField(default=3)
    source = models.CharField(max_length=100, default='system')
    added_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'رابط محظور'
        verbose_name_plural = 'الروابط المحظورة'
    
    def __str__(self):
        return f"{self.domain} - {self.threat_type}"


class UrlCache(models.Model):
    """
    Phase 3 — Server-side URL result cache.
    Layer 2 in the caching stack: Redis (L1) → UrlCache (L2) → VT Scan.
    Hash = SHA-256(normalized_url) — matches Flutter's computeUrlHash().
    """
    url_hash = models.CharField(max_length=64, primary_key=True)
    url = models.URLField(max_length=2000)
    result = models.CharField(max_length=50)          # 'safe' | 'malicious' | 'suspicious'
    threat_level = models.CharField(max_length=20, default='none')  # 'none'|'low'|'medium'|'high'
    risk_score = models.IntegerField(default=0)
    scanned_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    class Meta:
        verbose_name = 'كاش الروابط'
        verbose_name_plural = 'كاش الروابط'
        indexes = [
            models.Index(fields=['url_hash']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"{self.url[:60]} [{self.result}] expires={self.expires_at}"
