# apps/feedback/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import AppRating
from django.db import transaction

class AppRatingView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            rating = request.user.app_rating
            return Response({
                "rating": rating.rating,
                "comment": rating.comment
            })
        except AppRating.DoesNotExist:
            return Response({
                "rating": None,
                "comment": ""
            })

    @transaction.atomic
    def put(self, request):
        rating_value = request.data.get("rating")
        comment = request.data.get("comment", "")

        if rating_value is None:
            return Response({"detail": "Rating is required"}, status=400)
            
        try:
            rating_int = int(rating_value)
            if not (1 <= rating_int <= 5):
                raise ValueError()
        except ValueError:
            return Response({"detail": "Invalid rating value (1-5)"}, status=400)

        rating_obj, created = AppRating.objects.update_or_create(
            user=request.user,
            defaults={
                "rating": rating_int,
                "comment": comment
            }
        )

        return Response({
            "success": True,
            "message": "Rating saved",
            "created": created,
            "rating": rating_obj.rating,
            "comment": rating_obj.comment
        })
