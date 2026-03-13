# apps/accounts/views.py
import secrets
import logging
from datetime import timedelta
from django.contrib.auth import authenticate
from django.core.mail import EmailMessage
from django.utils import timezone
from django.utils.crypto import get_random_string
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

from .models import User, EmailVerification, IPAttempt
from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer,
    SendOTPSerializer, VerifyOTPSerializer, ResendOTPSerializer
)
from .email_templates import EMAIL_VERIFICATION_TEMPLATE, PASSWORD_RESET_TEMPLATE

logger = logging.getLogger(__name__)

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def track_ip_attempt(ip):
    now = timezone.now()
    ip_attempt, created = IPAttempt.objects.get_or_create(ip_address=ip)
    
    # Reset count if last attempt was more than 10 minutes ago
    if now - ip_attempt.last_attempt_at > timedelta(minutes=10):
        ip_attempt.count = 1
    else:
        ip_attempt.count += 1
    
    ip_attempt.save()
    return ip_attempt.count

class RegisterView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'success': True,
                'user': UserSerializer(user).data,
                'tokens': {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                }
            }, status=status.HTTP_201_CREATED)
        return Response({'success': False, 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class SendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            name = serializer.validated_data['name']
            password = serializer.validated_data['password']
            purpose = request.data.get('purpose', 'register')

            # Rate limiting for email
            try:
                verification = EmailVerification.objects.get(email=email)
                now = timezone.now()
                
                # Check 60s cooldown
                if now - verification.last_request_at < timedelta(seconds=60):
                    return Response({
                        'success': False,
                        'message': 'يرجى الانتظار 60 ثانية قبل طلب رمز جديد'
                    }, status=status.HTTP_429_TOO_MANY_REQUESTS)
                
                # Check max 3 requests in 10 minutes
                if now - verification.last_request_at < timedelta(minutes=10):
                    if verification.request_count >= 3:
                        return Response({
                            'success': False,
                            'message': 'لقد تجاوزت حد طلب الرموز، يرجى المحاولة بعد 10 دقائق'
                        }, status=status.HTTP_429_TOO_MANY_REQUESTS)
                    verification.request_count += 1
                else:
                    verification.request_count = 1
                
                verification.last_request_at = now
                verification.purpose = purpose
                verification.name = name
                verification.set_password(password)
                
            except EmailVerification.DoesNotExist:
                verification = EmailVerification(
                    email=email,
                    name=name,
                    purpose=purpose
                )
                verification.set_password(password)

            # Secure OTP generation
            otp = ''.join([secrets.choice('0123456789') for _ in range(6)])
            verification.otp = otp
            verification.otp_attempts = 0 # Reset attempts
            verification.expires_at = timezone.now() + timedelta(minutes=5)
            verification.save()

            # Logging
            logger.info(f"OTP Requested: {email} (IP: {get_client_ip(request)})")

            subject = 'التأكد من حسابك - SafeClick'
            html_content = EMAIL_VERIFICATION_TEMPLATE.replace('{{OTP_CODE}}', otp)
            
            try:
                email_msg = EmailMessage(
                    subject,
                    html_content,
                    None,
                    [email]
                )
                email_msg.content_subtype = "html"
                email_msg.send(fail_silently=False)
            except Exception as e:
                logger.error(f"Email sending error: {e}")

            return Response({
                'success': True,
                'message': 'verification_sent'
            })
            
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        ip = get_client_ip(request)
        ip_count = track_ip_attempt(ip)
        
        # IP Rate limit: max 10 attempts in 10 minutes
        if ip_count > 10:
            logger.warning(f"IP Rate limit exceeded: {ip}")
            return Response({
                'success': False,
                'message': 'كثير من المحاولات من هذا الجهاز، يرجى الانتظار 10 دقائق'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)

        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            
            try:
                verification = EmailVerification.objects.get(email=email)
                now = timezone.now()
                
                # Lockout check
                if verification.lockout_until and now < verification.lockout_until:
                    return Response({
                        'success': False,
                        'message': 'تم حظر المحاولات مؤقتاً، يرجى المحاولة بعد 15 دقيقة'
                    }, status=status.HTTP_403_FORBIDDEN)
                
                # Expiry check
                if now > verification.expires_at:
                    return Response({
                        'success': False,
                        'message': 'الرمز منتهي الصلاحية'
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
                # OTP check
                if verification.otp != otp:
                    verification.otp_attempts += 1
                    if verification.otp_attempts >= 5:
                        verification.lockout_until = now + timedelta(minutes=15)
                        verification.save()
                        logger.warning(f"Account locked: {email}")
                        return Response({
                            'success': False,
                            'message': 'تجاوزت حد المحاولات، تم حظر الحساب لمدة 15 دقيقة'
                        }, status=status.HTTP_403_FORBIDDEN)
                    
                    verification.save()
                    logger.info(f"Failed OTP attempt: {email} (Attempt {verification.otp_attempts})")
                    return Response({
                        'success': False,
                        'message': f'الرمز غير صحيح (المتبقي {5 - verification.otp_attempts} محاولات)'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Success
                if verification.purpose == 'register':
                    if User.objects.filter(email=email).exists():
                         return Response({
                            'success': False,
                            'message': 'البريد الإلكتروني مسجل بالفعل'
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    user = User.objects.create_user(
                        email=email,
                        name=verification.name,
                        password='' # Will set actual hash next
                    )
                    user.password = verification.password # This is already hashed
                    user.is_email_verified = True
                    user.save()
                    
                    refresh = RefreshToken.for_user(user)
                    
                    logger.info(f"OTP Verified & Account Created: {email}")
                    verification.delete()
                    
                    return Response({
                        'success': True,
                        'message': 'Account created successfully',
                        'tokens': {
                            'access': str(refresh.access_token),
                            'refresh': str(refresh),
                        },
                        'user': UserSerializer(user).data
                    }, status=status.HTTP_201_CREATED)
                
                # For reset password
                return Response({
                    'success': True,
                    'message': 'otp_verified'
                })
                
            except EmailVerification.DoesNotExist:
                return Response({
                    'success': False,
                    'message': 'لم يتم العثور على طلب تحقق'
                }, status=status.HTTP_400_BAD_REQUEST)
                
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                verification = EmailVerification.objects.get(email=email)
                now = timezone.now()
                
                # Rate limit (60s)
                if now - verification.last_request_at < timedelta(seconds=60):
                     return Response({
                        'success': False,
                        'message': 'يرجى الانتظار 60 ثانية قبل إعادة الطلب'
                    }, status=status.HTTP_429_TOO_MANY_REQUESTS)
                
                # Use secrets for secure OTP
                otp = ''.join([secrets.choice('0123456789') for _ in range(6)])
                verification.otp = otp
                verification.otp_attempts = 0
                verification.last_request_at = now
                verification.expires_at = now + timedelta(minutes=5)
                verification.save()
                
                subject = 'رمز تحقق جديد - SafeClick'
                html_content = EMAIL_VERIFICATION_TEMPLATE.replace('{{OTP_CODE}}', otp)
                
                try:
                    email_msg = EmailMessage(
                        subject,
                        html_content,
                        None,
                        [email]
                    )
                    email_msg.content_subtype = "html"
                    email_msg.send(fail_silently=False)
                except Exception as e:
                    logger.error(f"Resend Email error: {e}")

                return Response({
                    'success': True,
                    'message': 'verification_sent'
                })
                
            except EmailVerification.DoesNotExist:
                return Response({
                    'success': False,
                    'message': 'لم يتم العثور على طلب تحقق'
                }, status=status.HTTP_400_BAD_REQUEST)
                
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            
            try:
                user = User.objects.get(name=username)
                if user.check_password(password):
                    if not user.is_active:
                        return Response({'success': False, 'message': 'هذا الحساب معطل'}, status=status.HTTP_401_UNAUTHORIZED)
                    
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'success': True,
                        'user': UserSerializer(user).data,
                        'tokens': {
                            'access': str(refresh.access_token),
                            'refresh': str(refresh),
                        }
                    })
                else:
                    return Response({'success': False, 'message': 'كلمة المرور غير صحيحة'}, status=status.HTTP_401_UNAUTHORIZED)
            except User.DoesNotExist:
                return Response({'success': False, 'message': 'المستخدم غير موجود'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'success': False, 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def patch(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        # Simply return success, JWT is stateless or blacklisted on client
        return Response({"success": True, "message": "Successfully logged out"}, status=status.HTTP_200_OK)

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'success': False, 'message': 'البريد الإلكتروني مطلوب'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            otp = ''.join([secrets.choice('0123456789') for _ in range(6)])
            now = timezone.now()
            
            verification, created = EmailVerification.objects.get_or_create(email=email)
            
            if not created and now - verification.last_request_at < timedelta(seconds=60):
                 return Response({'success': False, 'message': 'يرجى الانتظار دقيقة قبل طلب رمز استعادة جديد'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
            
            verification.otp = otp
            verification.purpose = 'reset'
            verification.otp_attempts = 0
            verification.last_request_at = now
            verification.expires_at = now + timedelta(minutes=5)
            verification.save()

            subject = 'استعادة كلمة المرور - SafeClick'
            html_content = PASSWORD_RESET_TEMPLATE.replace('{{OTP_CODE}}', otp)
            
            try:
                email_msg = EmailMessage(
                    subject,
                    html_content,
                    None,
                    [email]
                )
                email_msg.content_subtype = "html"
                email_msg.send(fail_silently=False)
            except Exception as e:
                logger.error(f"Forgot password email error: {e}")
            
            return Response({'success': True, 'message': 'verification_sent'})
            
        except User.DoesNotExist:
            return Response({'success': False, 'message': 'البريد الإلكتروني غير مسجل'}, status=status.HTTP_404_NOT_FOUND)

class VerifyResetOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response({'success': False, 'message': 'البريد الإلكتروني والرمز مطلوبان'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            verification = EmailVerification.objects.get(email=email, purpose='reset')
            now = timezone.now()

            if now > verification.expires_at:
                return Response({'success': False, 'message': 'الرمز منتهي الصلاحية'}, status=status.HTTP_400_BAD_REQUEST)

            if verification.otp != otp:
                verification.otp_attempts += 1
                verification.save()
                return Response({'success': False, 'message': 'الرمز غير صحيح'}, status=status.HTTP_400_BAD_REQUEST)

            return Response({'success': True, 'message': 'otp_verified'})
            
        except EmailVerification.DoesNotExist:
            return Response({'success': False, 'message': 'لم يتم العثور على طلب استعادة'}, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        new_password = request.data.get('password')

        if not all([email, otp, new_password]):
            return Response({'success': False, 'message': 'جميع الحقول مطلوبة'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            verification = EmailVerification.objects.get(email=email, purpose='reset')
            now = timezone.now()

            if now > verification.expires_at:
                return Response({'success': False, 'message': 'الرمز منتهي الصلاحية'}, status=status.HTTP_400_BAD_REQUEST)

            if verification.otp != otp:
                verification.otp_attempts += 1
                verification.save()
                return Response({'success': False, 'message': 'الرمز غير صحيح'}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            
            verification.delete()
            return Response({'success': True, 'message': 'Password reset successful'})
            
        except (EmailVerification.DoesNotExist, User.DoesNotExist):
             return Response({'success': False, 'message': 'خطأ في عملية التحقق'}, status=status.HTTP_400_BAD_REQUEST)