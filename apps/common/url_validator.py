from urllib.parse import urlparse
from rest_framework import serializers

def validate_safe_url(value):
    parsed = urlparse(value)

    if parsed.scheme not in ["http", "https"]:
        raise serializers.ValidationError("Invalid URL scheme")

    if not parsed.netloc:
        raise serializers.ValidationError("Invalid URL")

    return value
