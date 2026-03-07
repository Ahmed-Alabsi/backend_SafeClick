# apps/reports/models.py
import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone

class Report(models.Model):
    """نموذج البلاغات"""
    STATUS_CHOICES = [
        ('pending', 'قيد المراجعة'),
        ('reviewing', 'قيد التحقيق'),
        ('confirmed', 'تم التأكيد'),
        ('rejected', 'مرفوض'),
        ('resolved', 'تم الحل'),
    ]
    
    SEVERITY_CHOICES = [
        (1, 'منخفض'),
        (2, 'متوسط'),
        (3, 'عالي'),
        (4, 'خطير'),
        (5, 'حرج'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='reports'
    )
    
    # معلومات البلاغ
    link = models.URLField(max_length=2000, verbose_name='الرابط المشبوه')
    category = models.CharField(max_length=100, verbose_name='نوع التهديد')
    description = models.TextField(blank=True, verbose_name='وصف إضافي')
    severity = models.IntegerField(choices=SEVERITY_CHOICES, default=3, verbose_name='درجة الخطورة')
    
    # حالة البلاغ
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', verbose_name='الحالة')
    tracking_number = models.CharField(max_length=50, unique=True, null=True, blank=True, verbose_name='رقم التتبع')
    
    # معلومات المبلغ
    reporter_name = models.CharField(max_length=255, verbose_name='اسم المبلغ')
    reporter_email = models.EmailField(null=True, blank=True, verbose_name='البريد الإلكتروني للمبلغ')
    is_anonymous = models.BooleanField(default=False, verbose_name='بلغ بشكل مجهول')
    
    # نتائج التحقيق
    investigation_notes = models.TextField(blank=True, verbose_name='ملاحظات التحقيق')
    is_confirmed_threat = models.BooleanField(default=False, verbose_name='تهديد مؤكد')
    
    # تواريخ
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='تاريخ الإبلاغ')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='آخر تحديث')
    reviewed_at = models.DateTimeField(null=True, blank=True, verbose_name='تاريخ المراجعة')
    resolved_at = models.DateTimeField(null=True, blank=True, verbose_name='تاريخ الحل')
    
    class Meta:
        verbose_name = 'بلاغ'
        verbose_name_plural = 'البلاغات'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['tracking_number']),
        ]
    
    def __str__(self):
        return f"{self.tracking_number or 'بلاغ'} - {self.link[:50]}"
        
    @property
    def url(self):
        return self.link
        
    @property
    def reason(self):
        return self.category
    
    def save(self, *args, **kwargs):
        if not self.tracking_number:
            self.tracking_number = self._generate_tracking_number()
        super().save(*args, **kwargs)
    
    def _generate_tracking_number(self):
        """توليد رقم تتبع فريد"""
        import random
        import string
        
        prefix = 'RPT'
        timestamp = timezone.now().strftime('%y%m%d')
        random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        
        return f"{prefix}-{timestamp}-{random_part}"
    
    def confirm_threat(self, notes=""):
        """تأكيد التهديد وإضافته للقائمة السوداء"""
        self.status = 'confirmed'
        self.is_confirmed_threat = True
        self.investigation_notes = notes
        self.reviewed_at = timezone.now()
        self.save()
        
        # إضافة للقائمة السوداء
        from apps.scans.models import Blacklist
        import tldextract
        
        extracted = tldextract.extract(self.link)
        domain = f"{extracted.domain}.{extracted.suffix}"
        
        Blacklist.objects.get_or_create(
            link=self.link,
            defaults={
                'domain': domain,
                'threat_type': self.category,
                'severity': self.severity,
                'description': self.description or 'تم الإبلاغ عنه وتأكيده',
                'source': 'user_report'
            }
        )
    
    def reject_report(self, notes=""):
        """رفض البلاغ"""
        self.status = 'rejected'
        self.investigation_notes = notes
        self.reviewed_at = timezone.now()
        self.save()
    
    def resolve_report(self, notes=""):
        """حل البلاغ"""
        self.status = 'resolved'
        self.investigation_notes = notes
        self.resolved_at = timezone.now()
        self.save()

class ReportComment(models.Model):
    """تعليقات على البلاغات"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    
    content = models.TextField(verbose_name='محتوى التعليق')
    is_internal = models.BooleanField(default=False, verbose_name='داخلي (للمشرفين فقط)')
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['created_at']
    
    def __str__(self):
        return f"تعليق على {self.report.tracking_number}"