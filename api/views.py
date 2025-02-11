from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import update_last_login
from api.serializers import (
    RegisterSerializer,
    AppointmentSerializer,
    UserSerializer,
    # RoleSerializer,
    BulkRegisterSerializer,
)
from api.permissions import IsAdmin, IsPatient, IsDentist, IsReceptionist
from django.utils.timezone import now, timedelta
from django.db.models import Count

# from api.models import User
from api.models import Appointment, Role

import logging

logger = logging.getLogger(__name__)

User = get_user_model()


# --- admin Only View ---
class AdminOnlyView(APIView):
    """
    View accessible only to admin users.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        print(f"User: {request.user}, Roles: {request.user.roles.all()}")
        return Response({"message": "Welcome, admin!"})

class AdminAnalyticsView(APIView):
    """
    Provides aggregated analytics for the Admin Dashboard.
    Requires admin access.
    """
    permission_classes = [IsAuthenticated, IsAdmin]
    
    def get(self, request):
        try:
            # --- User Statistics ---
            total_users = User.objects.count()
            active_users = User.objects.filter(last_login__gte=now() - timedelta(days=7)).count()

            # Count users by role
            users_by_role = (
                User.objects.values("roles__name")
                .annotate(count=Count("id"))
                .order_by()
            )
            role_counts = {entry["roles__name"]: entry["count"] for entry in users_by_role}

            # --- Appointment Statistics ---
            total_appointments = Appointment.objects.count()

            appointment_statuses = (
                Appointment.objects.values("status")
                .annotate(count=Count("id"))
                .order_by()
            )
            appointment_counts = {entry["status"]: entry["count"] for entry in appointment_statuses}

            # --- User Growth in Last 7 Days ---
            recent_users = (
                User.objects.filter(date_joined__gte=now() - timedelta(days=7))
                .extra({"day": "date(date_joined)"})
                .values("day")
                .annotate(count=Count("id"))
                .order_by("day")
            )
            user_growth = [{"date": entry["day"], "new_users": entry["count"]} for entry in recent_users]

            # --- Most Active Users ---
            most_active_users = (
                User.objects.filter(last_login__gte=now() - timedelta(days=30))
                .order_by("-last_login")
                .values("first_name", "last_name", "last_login")[:5]
            )

            active_users_list = [
                {
                    "name": f"{user['first_name']} {user['last_name']}".strip() or "Unknown User",
                    "last_login": user["last_login"],
                }
                for user in most_active_users
            ]

            # --- Top Dentists by Appointments ---
            top_dentists = (
                User.objects.filter(roles__name="dentist")  # Case-insensitive role match
                .annotate(appointment_count=Count("dentist_appointments"))
                .order_by("-appointment_count")[:5]
            )
            top_dentists_list = [
                {"name": f"{dentist.first_name} {dentist.last_name}".strip(), "appointments": dentist.appointment_count}
                for dentist in top_dentists
            ]

            # --- Response Data ---
            analytics_data = {
                "total_users": total_users,
                "active_users": active_users,
                "users_by_role": role_counts,
                "total_appointments": total_appointments,
                "appointment_statuses": appointment_counts,
                "user_growth_last_7_days": user_growth,
                "most_active_users": active_users_list,
                "top_dentists_by_appointments": top_dentists_list,
            }

            return Response(analytics_data, status=200)

        except Exception as e:
            logger.error(f"Error fetching admin analytics: {str(e)}")
            return Response({"error": "Failed to fetch analytics data."}, status=500)


# --- Custom JWT Token Views ---
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        """
        Adds custom claims to the JWT token.
        Includes the user's roles.
        """
        token = super().get_token(user)
        token["roles"] = list(
            user.roles.values_list("name", flat=True)
        )  # Add all roles to the token
        return token

    def validate(self, attrs):
        """
        Validates user credentials and includes additional role information in the response.
        """
        data = super().validate(attrs)
        data["roles"] = list(
            self.user.roles.values_list("name", flat=True)
        )  # Include all roles in the response
        return data


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        """
        Override post method to include tokens and roles in HttpOnly cookies.
        """
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except AuthenticationFailed:
            return Response(
                {"detail": "No active account found with the given credentials."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Access and refresh tokens
        access_token = serializer.validated_data["access"]
        refresh_token = serializer.validated_data["refresh"]

        # Retrieve user's roles
        user = serializer.user
        roles = list(user.roles.values_list("name", flat=True))

        response = Response(
            {
                "message": "Login successful!",
                "roles": roles,  # Include roles in the response
            },
            status=status.HTTP_200_OK,
        )

        # Set tokens in HttpOnly cookies
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=True,  # Set to True in production
            samesite="None",  # Adjust based on your needs
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,  # Set to True in production
            samesite="None",
        )

        return response


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom Token Refresh View to handle refresh tokens stored in HttpOnly cookies.
    """

    def post(self, request, *args, **kwargs):
        # Extract the refresh token from the HttpOnly cookie
        print("All cookies in the request:", request.COOKIES)
        print("All headers in the request:", request.headers)
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            print("Refresh token not found in cookies.")
            # Token is missing
            return Response(
                {"detail": "Refresh token is missing."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Validate the refresh token explicitly
        try:
            token = RefreshToken(refresh_token)
            token.check_exp()  # Check if the token is expired
            print("Token is valid.")
        except TokenError as e:
            print("Invalid token:", str(e))
            return Response(
                {"detail": "Invalid refresh token."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Prepare data for the serializer
        data = {"refresh": refresh_token}
        serializer = self.get_serializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except InvalidToken:
            return Response(
                {"detail": "Invalid refresh token."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Extract the new access token from the serializer
        new_access_token = serializer.validated_data.get("access")
        if not new_access_token:
            return Response(
                {"detail": "Failed to generate a new access token."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Set the new access token in an HttpOnly cookie
        response = Response(
            {"message": "Token refreshed successfully!"}, status=status.HTTP_200_OK
        )
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            secure=True,  # Set to True in production
            samesite="Strict",  # Use "Lax" or "Strict" based on your CSRF strategy
        )

        return response


class LogoutView(APIView):
    """
    Logout user by clearing HttpOnly JWT cookies and blacklisting the refresh token.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logger.info(f"Logout request received from user: {request.user.email}")

        # Extract refresh token from cookies
        refresh_token = request.COOKIES.get("refresh_token")
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()  # Blacklist the refresh token
                logger.info(f"Blacklisted refresh token for user: {request.user.email}")
            except Exception as e:
                logger.error(f"Error blacklisting token: {str(e)}")

        # Clear JWT tokens from cookies
        response = Response({"message": "Logout successful!"}, status=status.HTTP_200_OK)
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")

        return response

# --- Register View ---
class RegisterView(APIView):
    """
    API endpoint for user registration with support for blood group, roles, and Dependent registration.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()

                # Build the response message
                response_message = {
                    "message": "User registered successfully!",
                    "user_type": "Dependent" if user.guardian else "Normal User",
                    "email": user.email,
                    "password": (
                        "Generated by the system"
                        if "USER-" in user.email
                        else "Provided by the user"
                    ),
                    "roles": list(
                        user.roles.values_list("name", flat=True)
                    ),  # Include all assigned roles
                }

                # Include guardian details if applicable
                if user.guardian:
                    response_message["guardian"] = {
                        "email": user.guardian.email,
                        "first_name": user.guardian.first_name,
                        "last_name": user.guardian.last_name,
                        "contact_info": user.guardian.contact_info,
                    }
                logger.info(f"User {user.email} registered successfully.")
                return Response(response_message, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Unexpected error during registration: {str(e)}")
                return Response(
                    {"error": "An unexpected error occurred."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        logger.warning(f"Validation failed for registration: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BulkRegisterView(APIView):
    """
    API endpoint for bulk user registration with inline guardian support.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request):
        # Instantiate the serializer with request data
        serializer = BulkRegisterSerializer(data=request.data)

        if serializer.is_valid():
            try:
                # Save validated users
                result = (
                    serializer.save()
                )  # result contains success_count, failed_count, and details

                # Construct response using serializer output
                logger.info(f"{result['success_count']} users registered successfully.")
                return Response(result, status=status.HTTP_201_CREATED)

            except Exception as e:
                logger.error(f"Unexpected error during bulk registration: {str(e)}")
                return Response(
                    {"error": "An unexpected error occurred."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        # Handle validation errors
        logger.warning(f"Validation failed for bulk registration: {serializer.errors}")
        response_data = {
            "success_count": 0,
            "failed_count": len(request.data.get("users", [])),
            "details": serializer.errors,  # Include validation errors in the response
        }
        return Response(response_data, status=status.HTTP_400_BAD_REQUEST)


# --- patient Data View ---
class PatientDataView(APIView):
    """
    View to allow patients and optionally other roles to access patient-specific data.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        roles = list(user.roles.values_list("name", flat=True))

        # Check if user is a patient or has specific access
        if "patient" in roles or "admin" in roles or "dentist" in roles:
            # Safely access patient-specific fields
            patient_data = {
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "contact_info": user.contact_info if user.contact_info else "N/A",
                "dob": user.dob.strftime("%Y-%m-%d") if user.dob else "N/A",
                "gender": user.gender if user.gender else "N/A",
            }

            logger.info(f"User {user.email} accessed patient data.")
            return Response(patient_data, status=status.HTTP_200_OK)

        logger.warning(f"Unauthorized access attempt by {user.email}.")
        return Response(
            {"detail": "You are not authorized to view this data."},
            status=status.HTTP_403_FORBIDDEN,
        )


# --- Secure View (General Authenticated Access) ---
class SecureView(APIView):
    """
    Secure endpoint to validate authentication and fetch user details.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return Response(
            {
                "message": "Authentication successful!",
                "user": {
                    "id": request.user.id,
                    "email": request.user.email,
                    "roles": [role.name for role in request.user.roles.all()],
                },
            }
        )


class ReceptionistManagePatientsView(APIView):
    """
    View for receptionists to manage patient records.
    """

    permission_classes = [IsAuthenticated, IsReceptionist]

    def get(self, request):
        """
        Retrieve a list of all patients.
        """
        patients = User.objects.filter(roles__name="patient").values(
            "id", "email", "first_name", "last_name", "contact_info", "gender"
        )
        return Response(list(patients), status=200)

    def post(self, request):
        """
        Add a new patient.
        """
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save(roles=["patient"])  # Assign 'patient' role
            return Response(
                {
                    "message": f"patient {user.first_name} {user.last_name} created successfully!"
                },
                status=201,
            )
        print("Validation errors:", serializer.errors)  # Add this for debugging
        return Response(serializer.errors, status=400)


# Appointment List and Create View
class AppointmentListView(ListCreateAPIView):
    """
    Single view for listing and creating appointments based on the user's active role.
    - Admins can view all appointments but cannot create new ones.
    - Dentists can view only their assigned appointments.
    - Receptionists can view all appointments and create new ones.
    - Patients can view only their own appointments.
    """

    serializer_class = AppointmentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        roles = list(user.roles.values_list("name", flat=True))  # Retrieve all user roles
        active_role = self.request.query_params.get("role")  # Get active role from frontend

        print(f"User Roles: {roles}, Active Role: {active_role}, User ID: {user.id}")

        if not active_role or active_role not in roles:
            return Appointment.objects.none()  # If no role is provided, return empty queryset

        # Return data based on the active role
        if active_role == "admin":
            return Appointment.objects.all()
        elif active_role == "receptionist":
            return Appointment.objects.all()
        elif active_role == "dentist":
            return Appointment.objects.filter(dentist=user)
        elif active_role == "patient":
            return Appointment.objects.filter(patient=user)

        return Appointment.objects.none()

    def create(self, request, *args, **kwargs):
        """
        Create a new appointment.
        - Receptionists can create appointments.
        - Admins, Dentists, and Patients cannot create appointments.
        """
        roles = list(request.user.roles.values_list("name", flat=True))
        active_role = request.query_params.get("role")

        if not active_role or active_role not in roles:
            return Response(
                {"detail": "Invalid role selected."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if active_role != "receptionist":
            return Response(
                {"detail": "Only receptionists can create appointments."},
                status=status.HTTP_403_FORBIDDEN,
            )

        return super().create(request, *args, **kwargs)

# Appointment Detail View
class AppointmentDetailView(RetrieveUpdateDestroyAPIView):
    """
    View to retrieve, update, or delete a specific appointment.
    - Receptionists can update or delete appointments.
    - Dentists and Patients can request updates (flagged for receptionists to review).
    """

    serializer_class = AppointmentSerializer
    queryset = Appointment.objects.all()
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        # Debug incoming request data
        print("Incoming Data:", request.data)
        user = request.user

        # Retrieve user roles
        roles = list(user.roles.values_list("name", flat=True))

        if "receptionist" in roles:
            # receptionist can fully update the appointment
            return super().update(request, *args, **kwargs)
        elif "dentist" in roles or "patient" in roles:
            # Dentists and Patients can only request updates
            update_request = request.data.get("status", "Update Requested")
            appointment = self.get_object()
            appointment.status = update_request  # Flag the update request
            appointment.save()
            return Response(
                {
                    "detail": f"Update requested by {'dentist' if 'dentist' in roles else 'patient'}. receptionist will review."
                },
                status=status.HTTP_202_ACCEPTED,
            )
        return Response(
            {"detail": "You are not authorized to update this appointment."},
            status=status.HTTP_403_FORBIDDEN,
        )

    def destroy(self, request, *args, **kwargs):
        # Only Receptionists can delete appointments
        if not request.user.roles.filter(name="receptionist").exists():
            return Response(
                {"detail": "Only receptionists can delete appointments."},
                status=status.HTTP_403_FORBIDDEN,
            )
        return super().destroy(request, *args, **kwargs)


# User List View with Role Filtering
class UserListView(ListCreateAPIView):
    """
    View to list and create users dynamically filtered by role.
    Only accessible by Admins.
    """

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

    def get_queryset(self):
        """
        Filter users dynamically by role if a 'role' query parameter is provided.
        """
        role = self.request.query_params.get("role")
        try:
            if role:
                return User.objects.filter(roles__name=role)
            return User.objects.all()
        except Exception as e:
            # Log the error (you can use logging instead of print in production)
            print(f"Error occurred while fetching users: {e}")
            logger.error(f"An error occurred: {str(e)}")
            return User.objects.none()  # Return an empty queryset to fail gracefully


# User Detail View for CRUD Operations
class UserDetailView(RetrieveUpdateDestroyAPIView):
    """
    View to retrieve, update, or delete a user.
    Only Admins can access this endpoint.
    """

    serializer_class = UserSerializer
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated, IsAdmin]

    def update(self, request, *args, **kwargs):
        try:
            user = self.get_object()
            print("request.data", request.data)

            # Inject the current email if not provided in request data
            if "email" not in request.data:
                request.data["email"] = user.email

            # Check if 'roles' is in the request data
            if "roles" in request.data:
                roles = request.data.get("roles")

                # Convert to list if roles is a string
                if isinstance(roles, str):
                    roles = [r.strip() for r in roles.split(",")]

                # Check if roles is now a valid list
                if not isinstance(roles, list):
                    return Response(
                        {"detail": "Roles should be a list of valid role names."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Validate and update roles
                valid_roles = Role.objects.filter(name__in=roles)
                invalid_roles = set(roles) - set(
                    valid_roles.values_list("name", flat=True)
                )
                if invalid_roles:
                    return Response(
                        {"detail": f"Invalid roles: {', '.join(invalid_roles)}."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Update roles for the user
                user.roles.set(valid_roles)
                logger.info(f"Roles updated for user {user.id}: {roles}")

            # Continue with default update logic for other fields
            return super().update(request, *args, **kwargs)

        except User.DoesNotExist:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return Response(
                {"detail": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# Role Management View
class RoleManagementView(APIView):
    """
    View to manage user roles dynamically.
    Only Admins can assign roles.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, pk):
        try:
            user = User.objects.get(id=pk)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )

        new_roles = request.data.get("roles")
        if not new_roles or not isinstance(new_roles, list):
            return Response(
                {"detail": "A list of roles is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        roles_to_assign = Role.objects.filter(name__in=new_roles)
        invalid_roles = set(new_roles) - set(role.name for role in roles_to_assign)
        if invalid_roles:
            return Response(
                {"detail": f"Invalid roles: {', '.join(invalid_roles)}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.roles.set(roles_to_assign)
        user.save()
        return Response(
            {
                "detail": "Roles updated successfully.",
                "roles": list(user.roles.values_list("name", flat=True)),
            },
            status=status.HTTP_200_OK,
        )
