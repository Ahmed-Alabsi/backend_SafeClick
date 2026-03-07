# apps/reports/serializers.py
from rest_framework import serializers
from .models import Report, ReportComment

class ReportSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.name', read_only=True)
    
    class Meta:
        model = Report
        fields = [
            'id', 'link', 'category', 'description', 'severity',
            'status', 'tracking_number', 'reporter_name',
            'is_anonymous', 'investigation_notes', 'is_confirmed_threat',
            'created_at', 'updated_at', 'reviewed_at', 'resolved_at',
            'user_name'
        ]
        read_only_fields = [
            'id', 'status', 'tracking_number', 'investigation_notes',
            'is_confirmed_threat', 'created_at', 'updated_at',
            'reviewed_at', 'resolved_at'
        ]

class CreateReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ['link', 'category', 'description', 'severity', 'is_anonymous']
    
    def validate_link(self, value):
        from apps.common.url_validator import validate_safe_url
        return validate_safe_url(value)

class ReportDetailSerializer(serializers.ModelSerializer):
    comments = serializers.SerializerMethodField()
    
    class Meta:
        model = Report
        fields = '__all__'
    
    def get_comments(self, obj):
        comments = obj.comments.all()
        user = self.context.get('request').user
        
        # تصفية التعليقات الداخلية
        if not user.is_staff:
            comments = comments.filter(is_internal=False)
        
        return ReportCommentSerializer(comments, many=True).data

class ReportCommentSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.name', read_only=True)
    
    class Meta:
        model = ReportComment
        fields = ['id', 'content', 'is_internal', 'created_at', 'user_name']
        read_only_fields = ['id', 'created_at', 'user_name']

class UpdateReportStatusSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Report.STATUS_CHOICES)
    notes = serializers.CharField(required=False, allow_blank=True)