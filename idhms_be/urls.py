from django.contrib import admin
from django.urls import path
from api.views import (
    RegisterView,
    BulkRegisterView,
    SecureView,
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    AdminOnlyView,
    PatientDataView,
    ReceptionistManagePatientsView,
    AppointmentListCreateView,
    AppointmentDetailView,
    UserListView,  # Generic list view for users (patients, dentists, receptionists)
    UserDetailView,  # User detail view for CRUD operations
    RoleManagementView,  # API to assign/retrieve roles
)

urlpatterns = [
    # Admin Panel
    path("admin/", admin.site.urls),
    # Authentication Endpoints
    path("api/login/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    # path("api/login/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/login/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh"),
    path("api/register/", RegisterView.as_view(), name="register"),
    path("api/register/bulk/", BulkRegisterView.as_view(), name="bulk_register"),
    # Secure General View
    path("api/secure/", SecureView.as_view(), name="secure_view"),
    # Role-Specific Endpoints
    path("api/admin/", AdminOnlyView.as_view(), name="admin_only"),
    path("api/patient/data/", PatientDataView.as_view(), name="patient_data"),
    path(
        "api/receptionist/manage-patients/",
        ReceptionistManagePatientsView.as_view(),
        name="receptionist_manage_patients",
    ),
    # Appointment CRUD Endpoints
    path("api/appointments/", AppointmentListCreateView.as_view(), name="appointments"),
    path(
        "api/appointments/<int:pk>/",
        AppointmentDetailView.as_view(),
        name="appointment_detail",
    ),
    # List and CRUD Endpoints for Users
    path("api/users/", UserListView.as_view(), name="user_list"),  # List all users
    # For Dentists: /api/users/?role=Dentist
    # For Receptionists: /api/users/?role=Receptionist
    # For Patients: /api/users/?role=Patient
    path(
        "api/users/<int:pk>/", UserDetailView.as_view(), name="user_detail"
    ),  # Retrieve/Update/Delete user
    path(
        "api/users/<int:pk>/roles/",
        RoleManagementView.as_view(),
        name="role_management",
    ),
]
