from django.conf import settings
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from users.models import User
import jwt
import urllib.parse  # For URL decoding
from datetime import datetime, timedelta, timezone


class JWTAuthentication(BaseAuthentication):
    # authenticate(): return a tuple of (user, token)
    # jwt: contains (header, payload, signature)
    def authenticate(self, request):
        # Generate both access and refresh tokens
        access_token = self.get_authorization_header(request)

        if not access_token:  # no access token
            return None

        # decode token : jwt, key, algorithms
        try:
            # Decode the token if it's URL-encoded
            access_token = urllib.parse.unquote(access_token)
            # Check for the 'Bearer' prefix and extract the token
            prefix, token = access_token.split()
            if prefix != "Bearer":
                raise exceptions.AuthenticationFailed("Invalid token prefix")

            decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            print("decoded", decoded)
            user_email = decoded.get("member_email")

            if not user_email:
                raise AuthenticationFailed("Invalid Token")

            user = User.objects.get(member_email=user_email)

            # check if the access token is expired
            if datetime.now(timezone.utc) > datetime.fromtimestamp(
                decoded["exp"], tz=timezone.utc
            ):
                # access token is expired, attempt to load refresh token from cookies
                refresh_token = request.COOKIES.get("refresh_token")
                if not refresh_token:
                    raise AuthenticationFailed(
                        "Access token expired and no fresh token provided"
                    )
                try:
                    # decode and verify refresh token
                    decoded_refresh = jwt.decode(
                        refresh_token, settings.SECRET_KEY, algorithms=["HS256"]
                    )
                    if decoded_refresh.get("member_email") != user_email:
                        raise AuthenticationFailed("Invalid refresh token")

                    # Check if the refresh token is expired
                    if datetime.now(timezone.utc) > datetime.fromtimestamp(
                        decoded_refresh["exp"], tz=timezone.utc
                    ):
                        raise AuthenticationFailed(
                            "Refresh token expired. Please log in again!"
                        )

                    # Generate a renewed access token
                    new_access_token = self.generate_access_token(user)

                    # return the user and new access token
                    return (user, new_access_token)
                except jwt.ExpiredSignatureError:
                    raise AuthenticationFailed("Refresh token has expired!")
                except jwt.DecodeError:
                    raise AuthenticationFailed("Error decoding refresh token")

            # access token is still valid and not expired
            return (user, access_token)

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Access token has expired")
        except jwt.DecodeError:
            raise AuthenticationFailed("Error decoding access token")
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")

    def get_authorization_header(self, request):
        auth_header = request.headers.get("Authorization")
        if auth_header is None:
            return None
        return auth_header

    def generate_access_token(self, user):
        if user:
            # set expiry time (access: 15 min, refresh: 7 days)
            access_token_expiry = datetime.now(timezone.utc) + timedelta(minutes=15)

            # jwt.encode(payload, key, algorithm)
            access_payload = {
                "memeber_id": user.member_id,
                "member_email": user.member_email,
                "exp": access_token_expiry,
            }

            # generate access_token and refresh_token
            access_token = jwt.encode(
                payload=access_payload, key=settings.SECRET_KEY, algorithm="HS256"
            )

            # Add "Bearer" prefix to the access token
            # access_token.decode() : convert the bytes-like object returned by 'jwt.encode()' into a string
            access_token_with_prefix = "Bearer " + access_token.decode("utf-8")

            return access_token_with_prefix
        return None

