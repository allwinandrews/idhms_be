from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from api.models import User

# Register the custom User model with Django's UserAdmin
@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ("username", "email", "role", "is_active", "is_staff")
    list_filter = ("role", "is_active", "is_staff")
    search_fields = ("username", "email")
    ordering = ("username",)

    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Personal info", {"fields": ("email",)}),
        (
            "Roles and Permissions",
            {"fields": ("role", "is_active", "is_staff", "is_superuser")},
        ),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )
