# users/models.py
from django.contrib.auth.models import (
    AbstractUser,
    AbstractBaseUser,
    PermissionsMixin,
    BaseUserManager,
)
from django.db import models
from common.models import CommonModel
import uuid
from datetime import timedelta
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def create_user(self, member_email, password=None, **extra_fields):
        if not member_email:
            raise ValueError("The Email field must be set")
        member_email = self.normalize_email(member_email)
        user = self.model(member_email=member_email, **extra_fields)
        # set the password if provided
        if password is not None:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, member_email, password=None, **extra_fields):
        if not password:
            raise ValueError("Superuser must have a password")
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(member_email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin, CommonModel):
    # GROUP_CHOICESE = [
    #     ("general", "일반"),  # (DB에 저장할 실제 값, display 값)
    #     ("staff", "스태프"),
    #     ("admin", "관리자"),
    # ]
    member_id = models.AutoField(primary_key=True)
    member_email = models.EmailField(max_length=100, unique=True)
    img_uuid = models.CharField(max_length=36, default=uuid.uuid4, editable=False)
    img_generate_count = models.PositiveSmallIntegerField(default=0)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    mem_waiting = models.BooleanField(default=False)  # 승인대기
    mem_number = models.CharField(max_length=20, blank=True, null=True)  # 전화번호
    # Use 'member_email' as the unique identifier for authentication
    USERNAME_FIELD = "member_email"

    # No additional required fields for creating a user via createsuperuser command
    # REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return f"{self.member_email} / {self.is_staff}"


class Image(CommonModel):
    img_id = models.AutoField(primary_key=True)
    member = models.ForeignKey(User, on_delete=models.CASCADE)
    img_url = models.CharField(max_length=255)
    keyword_input = models.TextField()
    generating_count = models.SmallIntegerField(default=0)
    style_code = models.CharField(max_length=20)
    expiration_date = models.DateTimeField(default=timezone.now() + timedelta(days=7))

    def __str__(self):
        return f"ID: {self.img_id}, Member: {self.member}, keyword: {self.keyword_input}, style: {self.style_code}, URL: {self.img_url}"
