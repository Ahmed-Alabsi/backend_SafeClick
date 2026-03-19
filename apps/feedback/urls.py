# apps/feedback/urls.py

from django.urls import path
from .views import AppRatingView

urlpatterns = [
    path("rating/", AppRatingView.as_view()),
]
