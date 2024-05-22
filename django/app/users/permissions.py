from rest_framework.permissions import BasePermission


class IsSuperUserOrAdmin(BasePermission):
    # custom permission class to allow access only to admin user

    def has_permission(self, request, view):
        return request.user and (request.user.is_superuser or request.user.is_staff)
