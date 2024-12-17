from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from api.models import User, Appointment, Billing


# Inline models for related objects
class AppointmentInline(admin.TabularInline):
    model = Appointment
    fk_name = "patient"  # Specify the ForeignKey to use for the inline
    extra = 0  # Show no extra blank forms by default
    readonly_fields = ("appointment_date", "status")  # Read-only fields


class BillingInline(admin.TabularInline):
    model = Billing
    extra = 0
    readonly_fields = ("amount", "billing_date")  # Read-only fields


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    Custom admin configuration for the User model.
    """

    list_display = (
        "email",
        "role",
        "is_active",
        "is_staff",
        "dob",
        "contact_info",
        "gender",
    )
    list_filter = ("role", "is_active", "is_staff", "gender")
    search_fields = ("email", "role")  # Search by email and role
    ordering = ("email",)  # Order by email instead of username

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {"fields": ("dob", "contact_info", "gender")}),
        (
            "Roles and Permissions",
            {"fields": ("role", "is_active", "is_staff", "is_superuser")},
        ),
        ("Important Dates", {"fields": ("last_login", "date_joined")}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "role",
                    "is_active",
                    "is_staff",
                ),
            },
        ),
    )
