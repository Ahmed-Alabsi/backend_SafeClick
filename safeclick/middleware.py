# safeclick/middleware.py
#
# Phase 6 — App Access Protection Middleware.
# Validates that requests to /api/* originate from the official Flutter client
# by checking the X-App-ID header and an HMAC-SHA256 signature.
#
# Configuration in settings.py:
#   APP_ID     = 'safeclick-flutter-client'
#   APP_SECRET = '<random 32-byte hex string>'

import hashlib
import hmac
import logging
import os

from django.conf import settings
from django.http import JsonResponse

logger = logging.getLogger(__name__)

# Paths that do NOT require app-signature (public health / admin endpoints)
_EXEMPT_PREFIXES = ('/admin/', '/__debug__/', '/static/', '/media/')

# These API paths are exempt from App-ID validation (login/register must work
# from first install before the app has fetched dynamic secrets)
_AUTH_EXEMPT = ('/api/auth/login/', '/api/auth/register/', '/api/auth/forgot-password/')


class AppAccessMiddleware:
    """
    Validates X-App-ID and X-App-Signature headers on all /api/* requests.

    Header protocol:
      X-App-ID:        <APP_ID from settings>
      X-App-Signature: HMAC-SHA256(APP_SECRET, method + path + body)

    The Flutter app computes the signature as:
      HmacSha256(APP_SECRET, "${method}${path}${sha256(body)}")
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.app_id = getattr(settings, 'APP_ID', 'safeclick-flutter-client')
        self.app_secret = getattr(settings, 'APP_SECRET', '').encode()

    def __call__(self, request):
        # Only protect /api/* routes
        if not request.path.startswith('/api/'):
            return self.get_response(request)

        # Exempt auth bootstrap paths
        for exempt in _AUTH_EXEMPT:
            if request.path.startswith(exempt):
                return self.get_response(request)

        # In DEBUG mode, skip signature check (dev convenience)
        if settings.DEBUG:
            return self.get_response(request)

        app_id_header = request.headers.get('X-App-ID', '')
        signature_header = request.headers.get('X-App-Signature', '')

        if not app_id_header or not signature_header:
            logger.warning(
                "[AppAccess] Missing headers from %s %s",
                request.META.get('REMOTE_ADDR'),
                request.path,
            )
            return JsonResponse(
                {'success': False, 'message': 'Access denied: missing app credentials'},
                status=403,
            )

        if app_id_header != self.app_id:
            logger.warning("[AppAccess] Invalid X-App-ID: %s", app_id_header)
            return JsonResponse(
                {'success': False, 'message': 'Access denied: invalid app ID'},
                status=403,
            )

        if self.app_secret:
            body_bytes = request.body or b''
            body_hash = hashlib.sha256(body_bytes).hexdigest()
            expected_payload = (
                request.method + request.path + body_hash
            ).encode()
            expected_sig = hmac.new(
                self.app_secret,
                expected_payload,
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(expected_sig, signature_header):
                logger.warning("[AppAccess] Invalid signature from %s", request.path)
                return JsonResponse(
                    {'success': False, 'message': 'Access denied: invalid signature'},
                    status=403,
                )

        return self.get_response(request)
