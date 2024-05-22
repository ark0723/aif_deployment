import os
import requests
from .models import User
from dotenv import load_dotenv  # dotenv 모듈을 임포트합니다.
from datetime import datetime, timedelta, timezone

load_dotenv()  # .env 파일을 로드합니다.

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import NotFound, ParseError
from rest_framework import status
from .serializers import MyInfoUserSerializer, UserSerializer
from django.contrib.auth.password_validation import validate_password

from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, login, logout

# 권한 부여
from rest_framework.permissions import IsAuthenticated

# jwt 인증
from app.authentication import JWTAuthentication
from users.permissions import IsSuperUserOrAdmin
import jwt
from django.conf import settings


# create access token and refresh token based on user-login
class JWTLogin(APIView):
    def post(self, request):
        member_email = request.data.get("member_email")
        password = request.data.get("password")
        is_staff = request.data.get("is_staff")

        if not member_email:
            raise ParseError("email or (email and password) is required.")

        user = authenticate(
            request, member_email=member_email, password=password, is_staff=is_staff
        )

        if user:
            # set expiry time (access: 15 min, refresh: 7 days)
            access_token_expiry = datetime.now(timezone.utc) + timedelta(minutes=15)
            refresh_token_expiry = datetime.now(timezone.utc) + timedelta(days=7)

            # jwt.encode(payload, key, algorithm)
            access_payload = {
                "memeber_id": user.member_id,
                "member_email": user.member_email,
                "exp": access_token_expiry,
            }
            refresh_payload = {
                "memeber_id": user.member_id,
                "member_email": user.member_email,
                "exp": refresh_token_expiry,
            }

            # generate access_token and refresh_token
            access_token = jwt.encode(
                payload=access_payload, key=settings.SECRET_KEY, algorithm="HS256"
            )

            refresh_token = jwt.encode(
                payload=refresh_payload, key=settings.SECRET_KEY, algorithm="HS256"
            )
            response = Response({"access_token": access_token})

            # set the refresh token in an HTTP-Only cookie
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                expires=refresh_token_expiry,
                secure=True,  # Set to True in production for HTTPS
                samesite="Strict",  # Adjust according to your needs, e.g., 'Lax' or 'None'
            )

            return response
        raise ParseError("Invalid credentials")


# /users [POST]
class UserCreate(APIView):
    def check_email(self, request):
        api_key = os.getenv("EMAIL_API_KEY")
        email = request.data.get("member_email")
        print(email)

        try:
            api_response = requests.get(
                f"https://api.zerobounce.net/v2/validate?api_key={api_key}&email={email}"
            )
            api_response.raise_for_status()

        except requests.exceptions.RequestException as e:
            return Response({"message": "API 요청에 실패했습니다."}, status=500)

        api_response_json = api_response.json()
        return api_response_json.get("status")

    def get_user_by_email(self, email):
        return User.objects.get(member_email=email)

    # 사용자 생성
    def post(self, request):
        # password, email 받아오기
        password = request.data.get("password")
        email = request.data.get("member_email")

        # check the email address is already exist
        try:
            user = self.get_user_by_email(email)
            return Response({"message": "이미 존재하는 이메일입니다."}, status=400)
        except:
            # check email
            email_status = self.check_email(request)
            if email_status == "invalid":
                return Response({"message": "유효하지 않은 이메일입니다."}, status=400)

            serializer = MyInfoUserSerializer(data=request.data)
            # Validate password if provided
            if password:
                try:
                    validate_password(password)
                except:
                    raise ParseError("Invalid Password")

            if serializer.is_valid():
                # Create new user object from serializer data
                user = serializer.save()

                # Set password if provided and save user
                if password:
                    user.set_password(password)
                    user.save()

                # Return serialized user data in response
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                # Handle serializer validation errors
                raise ParseError(serializer.errors)


# /userlist [GET]
class UserList(APIView):
    # admin or staff만 접근 가능
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsSuperUserOrAdmin]

    # 전체 유저 리스트
    def get(self, request):
        users = User.objects.all()  # 객체
        # object -> json (serializer), queryset이므로 many = True is required
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# /users/myinfo [GET, PUT]
class MyInfo(APIView):
    # mypage 접근은 당사자만 가능하도록
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = MyInfoUserSerializer(user)

        return Response(serializer.data)

    def put(self, request):
        user = request.user
        # user data update : data = request.data, partial = True
        serializer = MyInfoUserSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            user = serializer.save()  # user 객체 저장
            serializer = MyInfoUserSerializer(user)  # user 객체 -> json
            return Response(serializer.data)
        else:
            return Response(serializer.errors)


class UserDetail(APIView):
    # admin or staff만 접근 가능
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsSuperUserOrAdmin]

    # 특정 유저 불러오기
    def get_object(self, member_id):
        try:
            return User.objects.get(member_id=member_id)
        except User.DoesNotExist:
            raise NotFound

    def get(self, request, member_id):
        user = self.get_object(member_id=member_id)
        # serializer : object -> json
        serializer = MyInfoUserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# customize authentication logic
class CustomAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        is_staff = request.data.get("is_staff")
        member_email = request.data.get("member_email")
        password = request.data.get("password")

        if is_staff is None or member_email is None:
            return Response(
                {
                    "error": "Please provide email address or (email address and password)"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(
            member_email=member_email, password=password, is_staff=is_staff
        )

        if not user:
            return Response(
                {"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
            )

        token, created = Token.objects.get_or_create(user=user)
        return Response({"token": token.key}, status=status.HTTP_200_OK)


class Login(APIView):
    def post(self, request):
        member_email = request.data.get("member_email")
        password = request.data.get("password")
        is_staff = request.data.get("is_staff")

        if not member_email:
            raise ParseError("email or (email and password) is required.")

        user = authenticate(
            request, member_email=member_email, password=password, is_staff=is_staff
        )

        if user:
            login(request, user)  # Log in the authenticated user
            return Response({"message": "Login Success!"}, status=status.HTTP_200_OK)
        else:
            return Response(
                {"message": "Your email or password is not valid, try again!"},
                status=status.HTTP_403_FORBIDDEN,
            )


class Logout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print("header : ", request.headers)
        logout(request)

        return Response({"message": "logout!"}, status=status.HTTP_200_OK)

