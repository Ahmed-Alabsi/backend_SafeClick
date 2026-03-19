# apps/reports/views.py
import logging
from django.utils import timezone
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.shortcuts import get_object_or_404

from .models import Report, ReportComment
from .serializers import (
    ReportSerializer, CreateReportSerializer, ReportDetailSerializer,
    UpdateReportStatusSerializer, ReportCommentSerializer
)
from apps.scans.models import Blacklist
from django.db.models import Count, Avg
from django.db.models.functions import TruncDate, TruncMonth

logger = logging.getLogger(__name__)

class CreateReportView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        print("\n" + "="*50)
        print("📥 استقبال بلاغ جديد")
        print("="*50)
        print(f"المستخدم: {request.user.name}")
        print(f"البيانات المستقبلة: {request.data}")
        
        serializer = CreateReportSerializer(data=request.data)
        
        if serializer.is_valid():
            print("✅ البيانات صحيحة")
            
            # إنشاء البلاغ
            report = Report(
                user=request.user,
                link=serializer.validated_data['link'],
                category=serializer.validated_data['category'],
                description=serializer.validated_data.get('description', ''),
                severity=serializer.validated_data.get('severity', 3),
                is_anonymous=serializer.validated_data.get('is_anonymous', False)
            )
            
            # تعيين اسم المبلغ
            if not report.is_anonymous:
                report.reporter_name = request.user.name
                report.reporter_email = request.user.email
            else:
                report.reporter_name = 'مستخدم مجهول'
            
            report.save()
            print(f"✅ تم حفظ البلاغ برقم: {report.tracking_number}")
            print(f"📊 حالة البلاغ: {report.status}")
            
            return Response({
                'success': True,
                'message': 'تم استلام البلاغ بنجاح',
                'report': ReportSerializer(report).data
            }, status=status.HTTP_201_CREATED)
        
        print("❌ أخطاء في البيانات:")
        print(serializer.errors)
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class TrackReportView(APIView):
    """تتبع حالة البلاغ باستخدام رقم التتبع"""
    permission_classes = [AllowAny]
    
    def get(self, request, tracking_number):
        try:
            report = Report.objects.get(tracking_number=tracking_number)
            serializer = ReportSerializer(report)
            return Response({
                'success': True,
                'report': serializer.data
            })
        except Report.DoesNotExist:
            return Response({
                'success': False,
                'message': 'رقم التتبع غير صحيح'
            }, status=status.HTTP_404_NOT_FOUND)

class MyReportsView(generics.ListAPIView):
    """عرض بلاغات المستخدم"""
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Report.objects.filter(
            user=self.request.user,
            deleted_at__isnull=True
        ).order_by('-created_at')
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        # إحصائيات
        stats = {
            'total': queryset.count(),
            'pending': queryset.filter(status='pending').count(),
            'confirmed': queryset.filter(status='confirmed').count(),
            'resolved': queryset.filter(status='resolved').count(),
        }
        
        return Response({
            'success': True,
            'stats': stats,
            'reports': serializer.data
        })

class ReportDetailView(generics.RetrieveAPIView):
    """عرض تفاصيل بلاغ محدد"""
    serializer_class = ReportDetailSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Report.objects.filter(user=self.request.user)

class AdminReportListView(generics.ListAPIView):
    """عرض كل البلاغات (للمشرفين)"""
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if not self.request.user.is_staff:
            return Report.objects.none()
        
        queryset = Report.objects.all().order_by('-created_at')
        
        # فلترة حسب الحالة
        status = self.request.query_params.get('status')
        if status:
            queryset = queryset.filter(status=status)
        
        # فلترة حسب درجة الخطورة
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        return queryset

class UpdateReportStatusView(APIView):
    """تحديث حالة البلاغ (للمشرفين)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        if not request.user.is_staff:
            return Response({
                'success': False,
                'message': 'غير مصرح لك بهذا الإجراء'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = UpdateReportStatusSerializer(data=request.data)
        if serializer.is_valid():
            try:
                report = Report.objects.get(pk=pk)
                old_status = report.status
                new_status = serializer.validated_data['status']
                notes = serializer.validated_data.get('notes', '')
                
                # تحديث الحالة
                report.status = new_status
                report.investigation_notes = notes
                report.reviewed_at = timezone.now()
                
                if new_status in ['confirmed', 'resolved']:
                    report.resolved_at = timezone.now()
                
                report.save()
                
                # إذا تم تأكيد التهديد، أضفه للقائمة السوداء
                if new_status == 'confirmed' and not report.is_confirmed_threat:
                    report.confirm_threat(notes)
                
                logger.info(f"تم تحديث حالة البلاغ {report.tracking_number} من {old_status} إلى {new_status}")
                
                return Response({
                    'success': True,
                    'message': 'تم تحديث حالة البلاغ بنجاح',
                    'report': ReportSerializer(report).data
                })
                
            except Report.DoesNotExist:
                return Response({
                    'success': False,
                    'message': 'البلاغ غير موجود'
                }, status=status.HTTP_404_NOT_FOUND)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class AddCommentView(APIView):
    """إضافة تعليق على بلاغ"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        try:
            report = Report.objects.get(pk=pk)
            
            # التحقق من الصلاحية
            if report.user != request.user and not request.user.is_staff:
                return Response({
                    'success': False,
                    'message': 'غير مصرح لك بهذا الإجراء'
                }, status=status.HTTP_403_FORBIDDEN)
            
            content = request.data.get('content')
            is_internal = request.data.get('is_internal', False) and request.user.is_staff
            
            if not content:
                return Response({
                    'success': False,
                    'message': 'محتوى التعليق مطلوب'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            comment = ReportComment.objects.create(
                report=report,
                user=request.user,
                content=content,
                is_internal=is_internal
            )
            
            return Response({
                'success': True,
                'message': 'تم إضافة التعليق بنجاح',
                'comment': ReportCommentSerializer(comment).data
            })
            
        except Report.DoesNotExist:
            return Response({
                'success': False,
                'message': 'البلاغ غير موجود'
            }, status=status.HTTP_404_NOT_FOUND)

class ReportStatsView(APIView):
    """إحصائيات البلاغات (للمشرفين)"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if not request.user.is_staff:
            return Response({
                'success': False,
                'message': 'غير مصرح لك بهذا الإجراء'
            }, status=status.HTTP_403_FORBIDDEN)
        
        reports = Report.objects.all()
        
        # إحصائيات عامة
        total = reports.count()
        by_status = reports.values('status').annotate(count=Count('id'))
        by_severity = reports.values('severity').annotate(count=Count('id'))
        by_category = reports.values('category').annotate(count=Count('id')).order_by('-count')[:10]
        
        # متوسط وقت المعالجة
        resolved = reports.filter(resolved_at__isnull=False)
        avg_resolution_time = None
        if resolved.exists():
            total_time = sum(
                (r.resolved_at - r.created_at).total_seconds() / 3600
                for r in resolved
            )
            avg_resolution_time = total_time / resolved.count()
        
        # إحصائيات يومية
        daily = reports.annotate(
            date=TruncDate('created_at')
        ).values('date').annotate(
            count=Count('id')
        ).order_by('-date')[:30]
        
        return Response({
            'success': True,
            'stats': {
                'total': total,
                'by_status': by_status,
                'by_severity': by_severity,
                'top_categories': by_category,
                'avg_resolution_time_hours': round(avg_resolution_time, 2) if avg_resolution_time else None,
                'daily_stats': list(daily),
                'confirmed_threats': reports.filter(is_confirmed_threat=True).count(),
            }
        })
class DeleteReportSoftView(APIView):
    """??? ???? (Soft Delete)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        from django.shortcuts import get_object_or_404
        from django.utils import timezone
        report = get_object_or_404(Report, pk=pk, user=request.user)
        report.deleted_at = timezone.now()
        report.save()
        
        return Response({
            'success': True,
            'message': '?? ??? ?????? ?? ????? ?????'
        })

class DeleteAllReportsSoftView(APIView):
    """??? ???? ???????? (Soft Delete)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        from django.utils import timezone
        count = Report.objects.filter(
            user=request.user, 
            deleted_at__isnull=True
        ).update(deleted_at=timezone.now())
        
        return Response({
            'success': True,
            'message': f'تم حذف {count} بلاغ من السجل بنجاح'
        })

class RestoreReportSoftView(APIView):
    """استعادة بلاغ محذوف (Undo Soft Delete)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        from django.shortcuts import get_object_or_404
        report = get_object_or_404(Report, pk=pk, user=request.user)
        
        if report.deleted_at is None:
            return Response({
                'success': False,
                'message': 'البلاغ غير محذوف'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        report.deleted_at = None
        report.save(update_fields=['deleted_at'])
        
        return Response({
            'success': True,
            'message': 'تم استعادة البلاغ بنجاح'
        })

class RestoreReportsBulkView(APIView):
    """استعادة قائمة من البلاغات المحذوفة مؤقتاً (Undo Delete Bulk)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        report_ids = request.data.get('report_ids', [])
        if not report_ids:
            return Response({
                'success': False,
                'message': 'يجب تقديم قائمة معرفات البلاغات لاستعادتها'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        count = Report.objects.filter(
            user=request.user, 
            id__in=report_ids,
            deleted_at__isnull=False
        ).update(deleted_at=None)
        
        return Response({
            'success': True,
            'message': f'تم استعادة {count} بلاغ بنجاح',
            'restored_count': count
        })
