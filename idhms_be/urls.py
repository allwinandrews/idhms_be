from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from api.views import RegisterView, SecureView, CustomTokenObtainPairView

urlpatterns = [
    path("admin/", admin.site.urls),
    # JWT Token Endpoints
    # path("api/login/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/login/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/login/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # Authentication Endpoints
    path("api/register/", RegisterView.as_view(), name="register"),
    path("api/secure/", SecureView.as_view(), name="secure_view"),
]
