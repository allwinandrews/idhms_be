from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from api.models import User
from api.serializers import RegisterSerializer
from api.permissions import IsAdmin, IsPatient, IsDentist, IsReceptionist


# --- Admin Only View ---
class AdminOnlyView(APIView):
    """
    View accessible only to Admin users.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        return Response({"message": "Welcome, Admin!"})


# --- Custom JWT Token Views ---
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        """
        Adds custom claims to the JWT token.
        Includes the user's role.
        """
        token = super().get_token(user)
        token["role"] = user.role  # Ensure the User model has a 'role' field
        return token

    def validate(self, attrs):
        """
        Validates user credentials and includes additional role information in the response.
        """
        data = super().validate(attrs)
        data["role"] = self.user.role
        return data


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


# --- Login View ---
class LoginView(APIView):
    """
    API endpoint for user login.
    Authenticates a user and returns JWT tokens along with their role.
    """

    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")

        # Authenticate user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            if not user.is_active:
                return Response(
                    {"error": "User is inactive."}, status=status.HTTP_400_BAD_REQUEST
                )

            # Dynamically set the role for superusers
            role = (
                "Admin" if user.is_superuser else getattr(user, "role", "Receptionist")
            )

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            update_last_login(None, user)  # Update last login timestamp

            return Response(
                {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "role": role,  # Include user role in the response
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {"error": "Invalid username or password."},
            status=status.HTTP_401_UNAUTHORIZED,
        )


# --- Register View ---
class RegisterView(APIView):
    """
    API endpoint for user registration with validation for email, phone number, and date of birth.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "User registered successfully!"},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# --- Patient Data View ---
class PatientDataView(APIView):
    """
    View to allow authenticated patients to access their data.
    Only users with the role 'Patient' are allowed.
    """

    permission_classes = [IsAuthenticated, IsPatient]

    def get(self, request):
        user = request.user

        # Safely access patient-specific fields
        patient_data = {
            "username": user.username,
            "email": user.email,
            "phone_number": user.contact_info if user.contact_info else "N/A",
            "dob": user.dob.strftime("%Y-%m-%d") if user.dob else "N/A",
            "gender": user.gender if user.gender else "N/A",
        }

        return Response(patient_data, status=status.HTTP_200_OK)


# --- Secure View (General Authenticated Access) ---
class SecureView(APIView):
    """
    Example of a secure API endpoint.
    Accessible only to authenticated users.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "This is a secure view!"})
