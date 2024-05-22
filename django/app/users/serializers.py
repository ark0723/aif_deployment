from rest_framework import serializers
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"


class UserAnswerSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "member_email",
            "img_uuid",
            "img_generate_count",
        )


class MyInfoUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=False, write_only=True)

    class Meta:
        model = User
        fields = [
            "member_id",
            "member_email",
            "password",
            "is_staff",
            "is_superuser",
            "img_uuid",
            "img_generate_count",
            "mem_waiting",
            "mem_number",
        ]
