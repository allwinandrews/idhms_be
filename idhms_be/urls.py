from django.contrib import admin
from django.urls import path
from api.views import (
    # Authentication & Security
    RegisterView,
    BulkRegisterView,
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    LogoutView,
    SecureView,

    # Admin & User Management
    AdminOnlyView,
    AdminAnalyticsView,
    UserListView,
    UserDetailView,
    RoleManagementView,

    # Appointment Management
    AppointmentListView,
    AppointmentDetailView,
    # AdminAppointmentView,
    # DentistAppointmentView,
    # ReceptionistAppointmentView,
    # PatientAppointmentView,

    # # Billing & Payments
    # PaymentListView,
    # PaymentDetailView,
    # InvoiceListView,
    # InvoiceDetailView,
    # RefundProcessingView,

    # # Security & Logging
    # SecurityLogsView,
    # BlockUserView,

    # # Super Admin Controls
    # SuperAdminConfigView,
    # MaintenanceModeView,

    EnableMFAView,
    VerifyMFAView
)

urlpatterns = [
    # 🔹 **Admin Panel**
    path("admin/", admin.site.urls),

    # 🔹 **Authentication Endpoints**
    path("api/login/", CustomTokenObtainPairView.as_view(),
         name="token_obtain_pair"),
    path("api/auth/mfa/enable/", EnableMFAView.as_view(), name="enable_mfa"),
    path("api/auth/mfa/verify/", VerifyMFAView.as_view(), name="verify_mfa"),
    path("api/login/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh"),
    path("api/logout/", LogoutView.as_view(), name="logout"),
    path("api/register/", RegisterView.as_view(), name="register"),
    path("api/register/bulk/", BulkRegisterView.as_view(), name="bulk_register"),
    path("api/secure/", SecureView.as_view(), name="secure_view"),

    # 🔹 **User & Role Management**
    path("api/users/", UserListView.as_view(), name="user_list"),
    path("api/users/<int:pk>/", UserDetailView.as_view(), name="user_detail"),
    path("api/users/<int:pk>/roles/",
         RoleManagementView.as_view(), name="role_management"),

    # 🔹 **Admin-Specific Endpoints**
    path("api/admin/", AdminOnlyView.as_view(), name="admin_only"),
    path("api/admin/analytics/", AdminAnalyticsView.as_view(),
         name="admin_analytics"),

    # 🔹 **Appointments (Role-Based Separation)**
    # path("api/admin/appointments/", AdminAppointmentView.as_view(),
    #      name="admin_appointments"),
    # path("api/dentist/appointments/", DentistAppointmentView.as_view(),
    #      name="dentist_appointments"),
    # path("api/receptionist/appointments/",
    #      ReceptionistAppointmentView.as_view(), name="receptionist_appointments"),
    # path("api/patient/appointments/", PatientAppointmentView.as_view(),
    #      name="patient_appointments"),
    path("api/appointments/<int:pk>/",
         AppointmentDetailView.as_view(), name="appointment_detail"),

    # 🔹 **Billing & Payments**
    # path("api/payments/", PaymentListView.as_view(), name="payments"),
    # path("api/payments/<int:pk>/",
    #      PaymentDetailView.as_view(), name="payment_detail"),
    # path("api/payments/refund/<int:pk>/",
    #      RefundProcessingView.as_view(), name="refund_processing"),
    # path("api/invoices/", InvoiceListView.as_view(), name="invoices"),
    # path("api/invoices/<int:pk>/",
    #      InvoiceDetailView.as_view(), name="invoice_detail"),

    # # 🔹 **Security & Logging**
    # path("api/security/logs/", SecurityLogsView.as_view(), name="security_logs"),
    # path("api/security/block-user/", BlockUserView.as_view(), name="block_user"),

    # # 🔹 **Super Admin Controls**
    # path("api/superadmin/config/", SuperAdminConfigView.as_view(),
    #      name="superadmin_config"),
    # path("api/superadmin/maintenance/",
    #      MaintenanceModeView.as_view(), name="maintenance_mode"),
]
