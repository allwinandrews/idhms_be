from django.shortcuts import render
from rest_framework.views import APIView
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
)
from api.permissions import IsAdmin, IsPatient, IsDentist, IsReceptionist

# from api.models import User
from api.models import Appointment


User = get_user_model()


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
        email = request.data.get("email")
        password = request.data.get("password")

        # Authenticate user using email
        user = authenticate(request, username=email, password=password)

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
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "contact_info": user.contact_info if user.contact_info else "N/A",
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


class ReceptionistManagePatientsView(APIView):
    # View for receptionists to manage patient records.

    permission_classes = [IsAuthenticated, IsReceptionist]

    def get(self, request):
        """
        Retrieve a list of all patients.
        """
        patients = User.objects.filter(role="Patient")
        serialized_patients = [
            {
                "id": patient.id,
                "email": patient.email,
                "first_name": patient.first_name,
                "last_name": patient.last_name,
                "contact_info": patient.contact_info,
                "gender": patient.gender,
            }
            for patient in patients
        ]
        return Response(serialized_patients, status=200)

    def post(self, request):
        # Extract patient details from request
        first_name = request.data.get("first_name")
        last_name = request.data.get("last_name")
        email = request.data.get("email")  # Allow input for real email
        contact_info = request.data.get("contact_info", "")
        dob = request.data.get("dob")
        gender = request.data.get("gender")

        # Basic validations
        errors = {}
        if not first_name:
            errors["first_name"] = "First name is required."
        if not last_name:
            errors["last_name"] = "Last name is required."
        if not email:
            errors["email"] = "Email is required."
        if not dob:
            errors["dob"] = "Date of birth is required."
        if gender not in ["Male", "Female", "Other"]:
            errors["gender"] = "Gender must be Male, Female, or Other."

        # Return detailed validation errors if any
        if errors:
            return Response(errors, status=400)

        # Check for email uniqueness
        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already exists."}, status=400)

        # Create the patient user
        patient = User.objects.create_user(
            email=email,
            password="default_password",  # Default password; can be updated later
            role="Patient",
            dob=dob,
            contact_info=contact_info,
            gender=gender,
            first_name=first_name,
            last_name=last_name,
        )

        return Response(
            {
                "message": f"Patient {patient.first_name} {patient.last_name} created successfully!"
            },
            status=201,
        )


# Appointment List and Create View
class AppointmentListCreateView(ListCreateAPIView):
    """
    View to list and create appointments.
    - Receptionists have full CRUD access.
    - Dentists can list appointments assigned to them.
    - Patients can list their own appointments.
    """

    serializer_class = AppointmentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        print(f"User Role: {user.role}, User ID: {user.id}")
        if user.role == "Receptionist":
            return Appointment.objects.all()
        elif user.role == "Dentist":
            print(f"Querying appointments for Dentist ID: {user.id}")
            return Appointment.objects.filter(dentist=user)
        elif user.role == "Patient":
            return Appointment.objects.filter(patient=user)
        return Appointment.objects.none()

    def create(self, request, *args, **kwargs):
        # Only Receptionists can create appointments
        if request.user.role != "Receptionist":
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
        appointment = self.get_object()

        if user.role == "Receptionist":
            # Receptionist can fully update the appointment
            return super().update(request, *args, **kwargs)
        elif user.role in ["Dentist", "Patient"]:
            # Dentists and Patients can only request updates
            update_request = request.data.get("status", "Update Requested")
            appointment.status = update_request  # Flag the update request
            appointment.save()
            return Response(
                {
                    "detail": f"Update requested by {user.role}. Receptionist will review."
                },
                status=status.HTTP_202_ACCEPTED,
            )
        return Response(
            {"detail": "You are not authorized to update this appointment."},
            status=status.HTTP_403_FORBIDDEN,
        )

    def destroy(self, request, *args, **kwargs):
        # Only Receptionists can delete appointments
        if request.user.role != "Receptionist":
            return Response(
                {"detail": "Only receptionists can delete appointments."},
                status=status.HTTP_403_FORBIDDEN,
            )
        return super().destroy(request, *args, **kwargs)


# User List View with Role Filtering
class UserListView(ListCreateAPIView):
    """
    View to list users dynamically filtered by role.
    Admins can access this endpoint.
    """

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

    def get_queryset(self):
        role = self.request.query_params.get("role")
        if role:
            return User.objects.filter(role=role)
        return User.objects.all()


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
        # Ensure Admins can update the role
        user = self.get_object()
        if "role" in request.data:
            user.role = request.data["role"]
        return super().update(request, *args, **kwargs)


# Role Management View
class RoleManagementView(APIView):
    """
    View to manage user roles dynamically.
    Only Admins can assign roles.
    """

    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request):
        user_id = request.data.get("user_id")
        new_role = request.data.get("role")

        if not user_id or not new_role:
            return Response(
                {"detail": "User ID and Role are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(id=user_id)
            user.role = new_role
            user.save()
            return Response(
                {"detail": f"Role updated to {new_role} for user {user.email}."},
                status=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
