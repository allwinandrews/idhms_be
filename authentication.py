from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Try to get the token from the Authorization header first
        header_auth = super().authenticate(request)
        if header_auth is not None:
            return header_auth

        # If no header is found, get token from cookies
        token = request.COOKIES.get("access_token")
        if not token:
            return None  # No token found, return None for unauthenticated users

        try:
            # Decode the JWT token properly using `AccessToken`
            validated_token = AccessToken(token)  # ✅ Fix: Ensure token is a dictionary, not a string
            user = self.get_user(validated_token)  # ✅ Fix: Pass decoded token
            return user, validated_token
        except Exception as e:
            raise AuthenticationFailed(f"Invalid token: {str(e)}")
