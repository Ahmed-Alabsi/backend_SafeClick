# apps/scans/admin.py
from django.contrib import admin
from django.utils.html import format_html
from .models import Scan, Blacklist

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = [
        'id_short',
        'url_short',
        'status_colored',
        'score_colored',
        'user_email',
        'timestamp_display',
        'threats_badge',
        'source_badge'
    ]
    
    list_filter = ['safe', 'source', 'created_at']
    search_fields = ['url', 'domain', 'user__email', 'id']
    list_per_page = 25
    ordering = ['-created_at']
    
    fieldsets = (
        ('معلومات الفحص', {
            'fields': ('url', 'domain', 'user', 'source', 'ip_address')
        }),
        ('النتائج', {
            'fields': ('safe', 'result', 'risk_score', 'threats_count')
        }),
        ('التفاصيل الفنية', {
            'fields': ('details', 'threats_found', 'response_time', 'server_info')
        }),
        ('تواريخ الفحص', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def id_short(self, obj):
        return str(obj.id)[:8] + '...'
    id_short.short_description = 'المعرف'
    
    def url_short(self, obj):
        return obj.url[:50] + '...' if len(obj.url) > 50 else obj.url
    url_short.short_description = 'الرابط'
    
    def status_colored(self, obj):
        if obj.safe == True:
            return format_html('<span style="color: green; font-weight: bold;">✅ آمن</span>')
        elif obj.safe == False:
            return format_html('<span style="color: red; font-weight: bold;">🔴 خطير</span>')
        else:
            return format_html('<span style="color: orange; font-weight: bold;">⚠️ مشبوه</span>')
    status_colored.short_description = 'الحالة'
    
    def score_colored(self, obj):
        color = 'green' if obj.risk_score >= 70 else 'orange' if obj.risk_score >= 40 else 'red'
        return format_html('<div style="background-color: {}; color: white; padding: 2px 6px; border-radius: 4px; text-align: center; font-weight: bold;">{}%</div>', color, obj.risk_score)
    score_colored.short_description = 'مستوى الأمان'
    
    def user_email(self, obj):
        return obj.user.email if obj.user else 'غير مسجل'
    user_email.short_description = 'المستخدم'
    
    def timestamp_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M')
    timestamp_display.short_description = 'التاريخ'
    
    def threats_badge(self, obj):
        if obj.threats_count > 0:
            return format_html('<span style="background: #ff4444; color: white; padding: 3px 8px; border-radius: 10px;">⚠️ {} تهديد</span>', obj.threats_count)
        return format_html('<span style="color: green;">✅ نظيف</span>')
    threats_badge.short_description = 'التهديدات'
    
    def source_badge(self, obj):
        return format_html('<span style="background: #333; color: white; padding: 2px 5px; border-radius: 4px; font-size: 0.9em;">{}</span>', obj.source)
    source_badge.short_description = 'المصدر'
    
    readonly_fields = ['id', 'created_at', 'updated_at']


@admin.register(Blacklist)
class BlacklistAdmin(admin.ModelAdmin):
    list_display = ['domain', 'threat_type', 'severity', 'source', 'added_at']
    list_filter = ['threat_type', 'severity']
    search_fields = ['domain', 'link']