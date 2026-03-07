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
    """فحص رابط جديد — Phase 5: Authentication Required."""
    permission_classes = [IsAuthenticated]  # Anonymous access disabled
    throttle_scope = 'scan'  # 10/min per user defined in settings

    def post(self, request):
        logger.info("[SCAN] طلب فحص رابط من: %s", request.user.email)
        
        serializer = ScanLinkSerializer(data=request.data)
        
        if serializer.is_valid():
            link = serializer.validated_data['link']
            logger.info("[SCAN] الرابط: %s", link)

            try:
                user = request.user
                service_result = scan_url(link, user)
                
                logger.info("[SCAN] نتيجة: %s%%  %s", service_result.get('risk_score'), service_result.get('result'))
                response_data = {
                    'url': service_result.get('url'),
                    'result': service_result.get('result'),
                    'risk_score': service_result.get('risk_score'),
                    'scanned_at': service_result.get('scanned_at'),
                    
                    # Legacy fallback fields
                    'safe': service_result.get('safe'),
                    'score': service_result.get('score'),
                    'domain': service_result.get('domain'),
                    'final_status': service_result.get('final_status'),
                    'final_message': service_result.get('final_message'),
                    'details': service_result.get('details', [])
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
            .filter(user=request.user)
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
