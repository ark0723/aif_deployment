from django.urls import path
from . import views

urlpatterns = [
    path("create", views.UserCreate.as_view()),
    path("list", views.UserList.as_view()),
    path("myinfo", views.MyInfo.as_view()),
    path("<int:member_id>", views.UserDetail.as_view()),
    path("login", views.Login.as_view()),
    path("logout", views.Logout.as_view()),
    path("jwt-login", views.JWTLogin.as_view()),  # jwt authentication
]
