from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User


class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ("member_email", "is_staff", "is_active")
    list_filter = ("is_staff", "is_active", "mem_waiting")
    fieldsets = (
        (None, {"fields": ("member_email", "password")}),
        (
            "Permissions",
            {"fields": ("is_staff", "is_active", "groups", "user_permissions")},
        ),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "member_email",
                    "password1",
                    "password2",
                    "is_staff",
                    "is_active",
                ),
            },
        ),
    )
    search_fields = ("member_email", "img_uuid")
    ordering = ("member_email",)  # Change 'ordering' to use 'member_email'

    # pagination
    list_per_page = 10
    # add action
    actions = ("approval",)

    def approval(self, request, queryset):
        # 선택된 게시글들에 대해 'likes' 수를 1씩 증가
        for member in queryset:
            member.mem_waiting = False
            member.save()

    approval.short_description = "staff 가입 승인"


admin.site.register(User, CustomUserAdmin)
