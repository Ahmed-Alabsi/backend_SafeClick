# apps/feedback/models.py

from django.db import models
from django.conf import settings

class AppRating(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="app_rating"
    )
    rating = models.PositiveSmallIntegerField()
    comment = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user'], name='unique_user_rating')
        ]

    def __str__(self):
        return f"{self.user} - {self.rating}"
