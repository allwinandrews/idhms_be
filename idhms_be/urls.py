from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from api.views import (
    RegisterView,
    SecureView,
    CustomTokenObtainPairView,
    AdminOnlyView,
    PatientDataView,
    DentistAppointmentsView,
    ReceptionistManagePatientsView,
)

urlpatterns = [
    path("admin/", admin.site.urls),
    # Authentication Endpoints
    path("api/login/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/login/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/register/", RegisterView.as_view(), name="register"),
    path("api/secure/", SecureView.as_view(), name="secure_view"),
    # Role-Based Endpoints
    path("api/admin/", AdminOnlyView.as_view(), name="admin_only"),
    path("api/patient/data/", PatientDataView.as_view(), name="patient_data"),
    path(
        "api/appointments/",
        DentistAppointmentsView.as_view(),
        name="dentist_appointments",
    ),
    path(
        "api/receptionist/manage-patients/",
        ReceptionistManagePatientsView.as_view(),
        name="receptionist_manage_patients",
    ),
]
