# apps/scans/serializers.py
from rest_framework import serializers
from .models import Scan

class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = [
            'id', 'url', 'url_hash', 'domain', 'ip_address',
            'safe', 'score', 'risk_score', 'result', 'details', 'threats_found',
            'threats_count', 'response_time', 'server_info', 'created_at', 'timestamp'
        ]
    
    def to_representation(self, instance):
        """تنسيق البيانات للعرض"""
        data = super().to_representation(instance)
        
        # تنسيق التفاصيل كنصوص
        if isinstance(data.get('details'), list):
            data['details'] = [str(d) for d in data['details']]
        
        # Flutter Model Alignment
        data['ipAddress'] = data.get('ip_address')
        data['responseTime'] = data.get('response_time')
        data['timestamp'] = data.get('created_at')
        
        # إضافة الحالة النصية
        if data['safe'] == True:
            data['status_text'] = 'آمن'
            data['status_icon'] = '✅'
        elif data['safe'] == False:
            data['status_text'] = 'خطير'
            data['status_icon'] = '🔴'
        else:
            data['status_text'] = 'مشبوه'
            data['status_icon'] = '⚠️'
        
        return data


class ScanLinkSerializer(serializers.Serializer):
    link = serializers.URLField(required=True)
    scan_level = serializers.ChoiceField(choices=['basic', 'standard', 'deep'], default='deep', required=False)
    def validate_link(self, value):
        from apps.common.url_validator import validate_safe_url
        return validate_safe_url(value)