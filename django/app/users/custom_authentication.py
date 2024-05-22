from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model


class EmailAuthBackend(ModelBackend):
    def authenticate(
        self, request, member_email=None, password=None, is_staff=False, **kwargs
    ):
        User = get_user_model()
        print(f"Attempting authentication for member_email: {member_email}")
        if is_staff:
            if member_email is None or password is None:
                return None  # No credentials provided
            try:
                user = User.objects.get(member_email=member_email)
                if user.check_password(password):
                    print(f"User {user} authenticated successfully")
                    return user  # Authentication successful
            except User.DoesNotExist:
                print("User does not exist")
                return None  # User does not exist
        else:
            if member_email is None:
                return None
            try:
                user = User.objects.get(member_email=member_email)
                print(f"User {user} authenticated successfully")
                return user
            except User.DoesNotExist:
                print("User does not exist")
                return None
        print("Authentication failed")
        return None  # Authentication failed
