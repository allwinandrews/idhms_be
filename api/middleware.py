from django.utils.deprecation import MiddlewareMixin

class CookieToHeaderMiddleware(MiddlewareMixin):
    """
    Middleware to extract the JWT from cookies and add it to the request headers
    before authentication.
    """
    def process_request(self, request):
        if "access_token" in request.COOKIES and "Authorization" not in request.headers:
            request.META["HTTP_AUTHORIZATION"] = f"Bearer {request.COOKIES['access_token']}"
