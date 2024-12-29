from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth import get_user_model
from api.models import Appointment, Billing, Role

User = get_user_model()


# Inline models for related objects
class AppointmentInline(admin.TabularInline):
    model = Appointment
    fk_name = "patient"  # Specify the ForeignKey to use for the inline
    extra = 0  # Show no extra blank forms by default
    readonly_fields = ("appointment_date", "status")  # Read-only fields
    can_delete = False  # Disallow deletion via inline
    verbose_name = "Appointment"
    verbose_name_plural = "Appointments"


class BillingInline(admin.TabularInline):
    model = Billing
    extra = 0
    readonly_fields = ("amount", "billing_date")  # Read-only fields
    can_delete = False  # Disallow deletion via inline
    verbose_name = "Billing Record"
    verbose_name_plural = "Billing Records"


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    """
    Admin configuration for the Role model.
    """

    list_display = ("id", "name")
    search_fields = ("name",)
    ordering = ("name",)


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    Custom admin configuration for the User model.
    """

    # Display roles as a comma-separated list
    def get_roles(self, obj):
        return ", ".join([role.name for role in obj.roles.all()])

    get_roles.short_description = "Roles"

    list_display = (
        "email",
        "get_roles",  # Display multiple roles
        "is_active",
        "is_staff",
        "dob",
        "contact_info",
        "first_name",
        "last_name",
        "gender",
    )

    # Filter by roles (using the related Role model)
    list_filter = ("roles", "is_active", "is_staff", "gender")

    # Allow searching by email and roles
    search_fields = ("email", "roles__name")

    ordering = ("email",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            "Personal Info",
            {"fields": ("dob", "contact_info", "first_name", "last_name", "gender")},
        ),
        (
            "Roles and Permissions",
            {"fields": ("roles", "is_active", "is_staff", "is_superuser")},
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
                    "roles",  # Allow adding multiple roles during user creation
                    "is_active",
                    "is_staff",
                ),
            },
        ),
    )

    # Inline models for related objects
    inlines = [AppointmentInline, BillingInline]

    def save_model(self, request, obj, form, change):
        """
        Override save_model to validate roles assigned to a user.
        """
        # Ensure all assigned roles are valid
        valid_roles = Role.objects.all()
        assigned_roles = obj.roles.all()
        if not set(assigned_roles).issubset(set(valid_roles)):
            raise ValueError("Invalid roles assigned to the user.")

        # Save the model normally if validation passes
        super().save_model(request, obj, form, change)


@admin.register(Appointment)
class AppointmentAdmin(admin.ModelAdmin):
    """
    Admin configuration for the Appointment model.
    """

    list_display = ("patient", "dentist", "appointment_date", "status")
    list_filter = ("status", "appointment_date", "dentist")
    search_fields = ("patient__email", "dentist__email")
    ordering = ("appointment_date",)

    # Allow admin to only fetch recent appointments for performance
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related("patient", "dentist")  # Optimize DB queries


@admin.register(Billing)
class BillingAdmin(admin.ModelAdmin):
    """
    Admin configuration for the Billing model.
    """

    list_display = ("patient", "amount", "billing_date")
    list_filter = ("billing_date",)
    search_fields = ("patient__email",)
    ordering = ("billing_date",)

    # Allow admin to only fetch recent billing records for performance
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related("patient")  # Optimize DB queries
