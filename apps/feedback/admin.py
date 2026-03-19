from django.contrib import admin
from .models import AppRating

@admin.register(AppRating)
class AppRatingAdmin(admin.ModelAdmin):
    list_display = ('user', 'rating', 'created_at', 'updated_at')
    list_filter = ('rating', 'created_at')
    search_fields = ('user__username', 'comment')
    readonly_fields = ('created_at', 'updated_at')
