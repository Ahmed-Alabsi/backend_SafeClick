# apps/scans/views.py
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Scan
from .serializers import ScanResultSerializer, ScanLinkSerializer
from services.url_scan_service import scan_url
import logging

logger = logging.getLogger(__name__)

class ScanLinkView(APIView):
    """فحص رابط جديد — Phase 5/Guest Support: Authentication Optional but with stricter rate limiting for guests."""
    from rest_framework.throttling import UserRateThrottle

    class ScanRateThrottle(UserRateThrottle):
        rate = '20/min'

    permission_classes = [AllowAny]
    throttle_classes = [ScanRateThrottle]

    def post(self, request):
        user_identifier = request.user.email if request.user.is_authenticated else "Guest"
        logger.info("[SCAN] طلب فحص رابط من: %s", user_identifier)
        
        serializer = ScanLinkSerializer(data=request.data)
        
        if serializer.is_valid():
            link = serializer.validated_data['link']
            scan_level = serializer.validated_data.get('scan_level', 'deep')
            logger.info("[SCAN] الرابط: %s | مستوى الفحص: %s", link, scan_level)

            import time
            start_time = time.time()

            try:
                # If the user is authenticated, pass the user object, otherwise pass None
                user = request.user if request.user.is_authenticated else None
                service_result = scan_url(link, user, scan_level)
                
                duration = time.time() - start_time
                meta = service_result.get('meta', {})
                logger.info({
                    "event": "scan_completed",
                    "url": link,
                    "scan_level": scan_level,
                    "duration": round(duration, 2),
                    "status": service_result.get('result'),
                    "cache_hit": meta.get('cache_hit', False),
                    "ttl": meta.get('ttl', 0)
                })
                # Unified Model Alignment for Flutter ScanResult.fromJson
                response_data = {
                    'id': service_result.get('id') or f"scan_{int(time.time())}",
                    'link': service_result.get('url'),
                    'safe': service_result.get('safe'),
                    'score': service_result.get('risk_score'),
                    'message': service_result.get('final_message'),
                    'details': service_result.get('details', []),
                    'timestamp': service_result.get('scanned_at'),
                    'domain': service_result.get('domain'),
                    
                    # Telemetry (camelCase for Flutter)
                    'ipAddress': service_result.get('ip_address'),
                    'responseTime': service_result.get('response_time'),
                    'threats_count': service_result.get('threats_count', 0),
                    
                    # Cache / Rate Limit Visibility
                    'meta': service_result.get('meta', {}),
                    
                    # Legacy fallback
                    'final_status': service_result.get('final_status'),
                }
                
                return Response({
                    'success': True,
                    'result': response_data
                })
                
            except Exception as e:
                logger.error(f"خطأ في الفحص: {str(e)}")
                return Response({
                    'success': False,
                    'message': 'حدث خطأ أثناء الفحص'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class ScanHistoryView(APIView):
    """عرض سجل الفحوصات — Phase 3: optimized query"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Use .only() to avoid loading heavy JSON fields; limit to 50 most recent.
        scans = (
            Scan.objects
            .filter(user=request.user, deleted_at__isnull=True)
            .only('id', 'url', 'result', 'safe', 'risk_score', 'created_at', 'domain', 'threats_count')
            .order_by('-created_at')[:50]
        )
        serializer = ScanResultSerializer(scans, many=True)
        data = serializer.data
        return Response({
            'success': True,
            'history': data,
            'count': len(data),
        })

class DeleteScanSoftView(APIView):
    """حذف فحص من السجل (Soft Delete)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        from django.shortcuts import get_object_or_404
        from django.utils import timezone
        scan = get_object_or_404(Scan, pk=pk, user=request.user)
        scan.deleted_at = timezone.now()
        scan.save()
        
        return Response({
            'success': True,
            'message': 'تم حذف الفحص من السجل بنجاح'
        })

class DeleteAllScansSoftView(APIView):
    """حذف جميع الفحوصات (Soft Delete)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        from django.utils import timezone
        count = Scan.objects.filter(
            user=request.user, 
            deleted_at__isnull=True
        ).update(deleted_at=timezone.now())
        
        return Response({
            'success': True,
            'message': f'تم حذف {count} فحص من السجل بنجاح'
        })

class RestoreScanSoftView(APIView):
    """استعادة فحص محذوف (Undo Soft Delete)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, pk):
        from django.shortcuts import get_object_or_404
        scan = get_object_or_404(Scan, pk=pk, user=request.user)
        
        if scan.deleted_at is None:
            return Response({
                'success': False,
                'message': 'الفحص غير محذوف'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        scan.deleted_at = None
        scan.save(update_fields=['deleted_at'])
        
        return Response({
            'success': True,
            'message': 'تم استعادة الفحص بنجاح'
        })

class RestoreScansBulkView(APIView):
    """استعادة قائمة من الفحوصات المحذوفة مؤقتاً (Undo Delete Bulk)"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        scan_ids = request.data.get('scan_ids', [])
        if not scan_ids:
            return Response({
                'success': False,
                'message': 'يجب تقديم قائمة معرفات الفحوصات استعادتها'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        count = Scan.objects.filter(
            user=request.user, 
            id__in=scan_ids,
            deleted_at__isnull=False
        ).update(deleted_at=None)
        
        return Response({
            'success': True,
            'message': f'تم استعادة {count} فحص بنجاح',
            'restored_count': count
        })
