from django.contrib import admin
from django.utils.html import format_html
from .models import Report, ReportComment

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = [
        'tracking_number',
        'link_short',
        'category',
        'severity_badge',
        'status_badge',
        'reporter_info',
        'created_at_display',
        'is_confirmed_badge'
    ]
    
    list_filter = [
        'status',
        'category',
        'severity',
        'is_confirmed_threat',
        'created_at'
    ]
    
    search_fields = [
        'link',
        'tracking_number',
        'reporter_name',
        'description'
    ]
    
    list_per_page = 25
    ordering = ['-created_at']
    
    fieldsets = (
        ('معلومات البلاغ', {
            'fields': ('link', 'category', 'description', 'severity')
        }),
        ('حالة البلاغ', {
            'fields': ('status', 'is_confirmed_threat', 'investigation_notes')
        }),
        ('معلومات المبلغ', {
            'fields': ('reporter_name', 'reporter_email', 'is_anonymous', 'user'),
            'classes': ('collapse',)
        }),
        ('تواريخ مهمة', {
            'fields': ('created_at', 'reviewed_at', 'resolved_at'),
            'classes': ('collapse',)
        }),
        ('معلومات إضافية', {
            'fields': ('tracking_number',),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ['tracking_number', 'created_at']
    
    # ===== دوال مساعدة =====
    
    @admin.display(description='الرابط')
    def link_short(self, obj):
        return obj.link[:50] + '...' if len(obj.link) > 50 else obj.link
    
    @admin.display(description='الخطورة')
    def severity_badge(self, obj):
        colors = {
            1: ('🟢', 'green', 'منخفض'),
            2: ('🔵', 'blue', 'متوسط'),
            3: ('🟡', 'orange', 'عالي'),
            4: ('🟠', 'darkorange', 'خطير'),
            5: ('🔴', 'red', 'حرج')
        }
        emoji, color, text = colors.get(obj.severity, ('⚪', 'gray', 'غير محدد'))
        return format_html(
            '<span style="color: {}; font-weight: bold;">{} {}</span>',
            color,
            emoji,
            text
        )
    
    @admin.display(description='الحالة')
    def status_badge(self, obj):
        status_config = {
            'pending': ('🟡', 'orange', 'قيد المراجعة'),
            'reviewing': ('🔵', 'blue', 'قيد التحقيق'),
            'confirmed': ('🔴', 'red', 'تم التأكيد'),
            'rejected': ('⚪', 'gray', 'مرفوض'),
            'resolved': ('🟢', 'green', 'تم الحل')
        }
        emoji, color, text = status_config.get(obj.status, ('⚪', 'gray', obj.status))
        return format_html(
            '<span style="color: {}; font-weight: bold;">{} {}</span>',
            color,
            emoji,
            text
        )
    
    @admin.display(description='المبلغ')
    def reporter_info(self, obj):
        if obj.is_anonymous:
            return '🕵️ مجهول'
        return obj.reporter_name
    
    @admin.display(description='التاريخ')
    def created_at_display(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M')
    
    @admin.display(description='مؤكد')
    def is_confirmed_badge(self, obj):
        if obj.is_confirmed_threat:
            return format_html('<span style="color: red;">✅ مؤكد</span>')
        return '❌'
    
    # ===== إجراءات مخصصة =====
    actions = [
        'mark_as_reviewing',
        'mark_as_confirmed',
        'mark_as_resolved',
        'mark_as_rejected',
        'export_reports_csv'
    ]
    
    @admin.action(description='🔵 وضع قيد التحقيق')
    def mark_as_reviewing(self, request, queryset):
        updated = queryset.update(status='reviewing')
        self.message_user(request, f'تم تحديث {updated} بلاغ')
    
    @admin.action(description='🔴 تأكيد البلاغات')
    def mark_as_confirmed(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(
            status='confirmed',
            is_confirmed_threat=True,
            reviewed_at=timezone.now()
        )
        self.message_user(request, f'تم تأكيد {updated} بلاغ')
    
    @admin.action(description='🟢 وضع كتم الحل')
    def mark_as_resolved(self, request, queryset):
        from django.utils import timezone
        updated = queryset.update(
            status='resolved',
            resolved_at=timezone.now()
        )
        self.message_user(request, f'تم حل {updated} بلاغ')
    
    @admin.action(description='⚪ رفض البلاغات')
    def mark_as_rejected(self, request, queryset):
        updated = queryset.update(status='rejected')
        self.message_user(request, f'تم رفض {updated} بلاغ')
    
    @admin.action(description='📥 تصدير CSV')
    def export_reports_csv(self, request, queryset):
        import csv
        from django.http import HttpResponse
        from datetime import datetime
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="reports_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        writer = csv.writer(response)
        writer.writerow([
            'رقم التتبع',
            'الرابط',
            'النوع',
            'الخطورة',
            'الحالة',
            'المبلغ',
            'مؤكد',
            'تاريخ البلاغ'
        ])
        
        for report in queryset:
            writer.writerow([
                report.tracking_number,
                report.link,
                report.category,
                report.severity,
                report.status,
                'مجهول' if report.is_anonymous else report.reporter_name,
                'نعم' if report.is_confirmed_threat else 'لا',
                report.created_at.strftime('%Y-%m-%d %H:%M')
            ])
        
        return response


@admin.register(ReportComment)
class ReportCommentAdmin(admin.ModelAdmin):
    list_display = ['report_tracking', 'user_name', 'content_short', 'is_internal', 'created_at']
    list_filter = ['is_internal', 'created_at']
    search_fields = ['content', 'report__tracking_number', 'user__email']
    list_per_page = 20
    
    @admin.display(description='البلاغ')
    def report_tracking(self, obj):
        return obj.report.tracking_number
    
    @admin.display(description='المستخدم')
    def user_name(self, obj):
        return obj.user.name if obj.user else 'محذوف'
    
    @admin.display(description='التعليق')
    def content_short(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content