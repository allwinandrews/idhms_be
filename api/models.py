from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.crypto import get_random_string  # For generating unique baby IDs
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from datetime import date
from django.core.validators import RegexValidator

class CustomUserManager(BaseUserManager):
    """
    Custom user manager for handling user creation using email as the primary identifier.
    Provides methods to create regular users and superusers.
    """

    def create_user(self, email, password=None, roles=None, **extra_fields):
        """
        Creates and returns a regular user with an email, password, and optional roles.

        Args:
            email (str): User's email address (primary identifier).
            password (str, optional): User's password.
            roles (list, optional): List of role names to assign to the user.
            **extra_fields: Additional user fields.

        Returns:
            User: The created user instance.

        Raises:
            ValueError: If the email field is missing.
        """
        if not email:
            raise ValueError("The Email field is required.")

        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)

        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        # Assign roles if provided
        if roles:
            user.roles.set(roles)

        return user

    def create_superuser(self, email, password=None, roles=None, **extra_fields):
        """
        Creates and returns a superuser with an email, password, and optional roles.

        Args:
            email (str): Superuser's email address.
            password (str, optional): Superuser's password.
            roles (list, optional): List of role names to assign to the superuser.
            **extra_fields: Additional user fields.

        Returns:
            User: The created superuser instance.

        Raises:
            ValueError: If required superuser fields are not correctly set.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if not extra_fields.get("is_staff"):
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields.get("is_superuser"):
            raise ValueError("Superuser must have is_superuser=True.")

        roles = roles or ["admin"]  # Default role for superusers

        user = self.create_user(email, password, roles=[], **extra_fields)
        self._assign_roles(user, roles)  # Assign roles after creation
        return user

    def _assign_roles(self, user, roles):
        """
        Assigns roles to a user. Ensures that all roles exist before assignment.

        Args:
            user (User): The user instance.
            roles (list): List of role names to assign.

        Raises:
            ValidationError: If role assignment fails.
        """
        role_objects = []
        for role_name in roles:
            role, created = Role.objects.get_or_create(name=role_name)
            role_objects.append(role)

        user.roles.set(role_objects)



class Role(models.Model):
    """
    Role model for managing user roles.
    """

    name = models.CharField(
        max_length=20,
        unique=True,
        help_text="The unique name of the role (e.g., admin, patient, etc.).",
    )

    def __str__(self):
        return self.name


class User(AbstractUser):
    """
    Custom User model that supports multiple roles.
    """

    ROLE_CHOICES = [
        ("admin", "admin"),
        ("dentist", "dentist"),
        ("receptionist", "receptionist"),
        ("patient", "patient"),
    ]

    BLOOD_GROUP_CHOICES = [
        ("A+", "A+"),
        ("A-", "A-"),
        ("B+", "B+"),
        ("B-", "B-"),
        ("AB+", "AB+"),
        ("AB-", "AB-"),
        ("O+", "O+"),
        ("O-", "O-"),
    ]

    username = None  # Remove the username field
    email = models.EmailField(unique=True, db_index=True)
    roles = models.ManyToManyField(
        Role,
        related_name="users",
        blank=True,
        help_text=_("Assign one or more roles to the user."),
    )
    dob = models.DateField(blank=True, null=True)
    contact_info = models.CharField(
        max_length=15,
        blank=True,
        null=True,
        validators=[
            RegexValidator(
                regex=r"^\+?[1-9]\d{1,14}$",
                message="Enter a valid phone number in international format (e.g., +123456789).",
            )
        ],
    )
    gender = models.CharField(
        max_length=10,
        choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")],
        blank=True,
        null=True,
    )
    blood_group = models.CharField(
        max_length=3,
        choices=BLOOD_GROUP_CHOICES,
        blank=True,
        null=True,
    )
    guardian = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dependents",
        help_text=_("Guardian user responsible for this account (for babies)."),
    )
    guardian_contact_info = models.CharField(max_length=15, blank=True, null=True)
    guardian_relationship = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text=_("Relationship to the guardian."),
    )

    USERNAME_FIELD = "email"  # Use email as the unique identifier
    REQUIRED_FIELDS = []  # No additional required fields for superuser creation

    objects = CustomUserManager()

    def clean(self):
        super().clean()
        if (
            self.guardian
            and self.guardian.dob
            and self.guardian.dob >= date.today().replace(year=date.today().year - 18)
        ):
            raise serializers.ValidationError(
                {"guardian": "Guardian must be at least 18 years old."}
            )

    def __str__(self):
        roles = (
            ", ".join(self.roles.values_list("name", flat=True))
            if self.roles.exists()
            else "No Roles"
        )
        return f"{self.email} ({roles})"

class Appointment(models.Model):
    STATUS_CHOICES = [
        ("Scheduled", "Scheduled"),
        ("Completed", "Completed"),
        ("Cancelled", "Cancelled"),
    ]

    APPOINTMENT_TYPE_CHOICES = [
        ("checkup", "Checkup"),
        ("surgery", "Surgery"),
        ("consultation", "Consultation"),
    ]

    patient = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="patient_appointments",
    )
    dentist = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dentist_appointments",
    )
    appointment_date = models.DateTimeField()
    appointment_type = models.CharField(
        max_length=20, choices=APPOINTMENT_TYPE_CHOICES, default="checkup"
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="Scheduled"
    )

    # ✅ Fix: Add missing created_at and updated_at fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self):
        """Ensure the correct roles for patient and dentist."""
        if not self.patient.roles.filter(name="patient").exists():
            raise serializers.ValidationError(
                f"User {self.patient.email} must have the 'patient' role."
            )
        if self.dentist and not self.dentist.roles.filter(name="dentist").exists():
            raise serializers.ValidationError(
                f"User {self.dentist.email} must have the 'dentist' role."
            )

    def __str__(self):
        return f"Appointment for {self.patient.first_name} {self.patient.last_name} on {self.appointment_date}"


class Billing(models.Model):
    patient = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="billings",
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    billing_date = models.DateField()

    def clean(self):
        """
        Custom validation to ensure the correct role for the patient.
        """
        if not self.patient.roles.filter(name="patient").exists():
            raise serializers.ValidationError(
                f"User {self.patient.email} must have the 'patient' role."
            )

    def __str__(self):
        return f"Billing for {self.patient.first_name} {self.patient.last_name} - {self.amount}"
