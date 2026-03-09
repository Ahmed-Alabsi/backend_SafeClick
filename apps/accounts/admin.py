# apps/accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['email', 'name', 'scanned_links', 'detected_threats', 'accuracy_badge', 'is_active', 'is_staff', 'created_at']
    list_filter = ['is_active', 'is_staff', 'is_email_verified', 'created_at']
    search_fields = ['email', 'name', 'id']
    ordering = ['-created_at']
    list_per_page = 20
    
    fieldsets = (
        ('معلومات الحساب', {'fields': ('email', 'password')}),
        ('معلومات شخصية', {'fields': ('name', 'profile_image')}),
        ('إحصائيات المستخدم', {
            'fields': ('scanned_links', 'detected_threats', 'accuracy_rate'),
            'description': 'يتم تحديث هذه الإحصائيات تلقائياً عند قيام المستخدم بفحص الروابط.'
        }),
        ('الصلاحيات والحالة', {'fields': ('is_active', 'is_staff', 'is_superuser', 'is_email_verified')}),
        ('تواريخ هامة', {'fields': ('last_login', 'created_at')}),
    )
    
    readonly_fields = ['created_at', 'last_login', 'scanned_links', 'detected_threats', 'accuracy_rate']

    @admin.display(description='معدل الدقة')
    def accuracy_badge(self, obj):
        from django.utils.html import format_html
        color = 'green' if obj.accuracy_rate >= 80 else 'orange' if obj.accuracy_rate >= 50 else 'red'
        return format_html('<span style="color: {}; font-weight: bold;">{}%</span>', color, obj.accuracy_rate)