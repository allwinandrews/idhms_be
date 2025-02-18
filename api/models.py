import pyotp
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.crypto import get_random_string  # For generating unique baby IDs
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from datetime import date
from django.core.validators import RegexValidator


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, roles=None, dob=None, blood_group=None, contact_info=None, **extra_fields):
        if not email:
            raise ValueError("The Email field is required.")

        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)

        user = self.model(
            email=email,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)

        if roles:
            user.roles.set(roles)

        return user

    def create_superuser(self, email, password=None, roles=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        roles = roles or ["admin"]  # Default role for superusers

        user = self.create_user(email, password, roles=[], **extra_fields)
        self._assign_roles(user, roles)  # Assign roles after creation
        return user


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
    Custom User model that supports multiple roles and MFA authentication.
    """

    ROLE_CHOICES = [
        ("admin", "admin"),
        ("dentist", "dentist"),
        ("receptionist", "receptionist"),
        ("patient", "patient"),
    ]

    username = None  # Remove the username field
    email = models.EmailField(unique=True, db_index=True)
    roles = models.ManyToManyField(
        "Role",
        related_name="users",
        blank=True,
        help_text="Assign one or more roles to the user.",
    )
    gender = models.CharField(
        max_length=10,
        choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")],
        blank=True,
        null=True,
    )
    dob = models.DateField(blank=True, null=True)
    blood_group = models.CharField(max_length=3, blank=True, null=True)
    contact_info = models.CharField(max_length=15, blank=True, null=True)
    guardian = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dependents",
    )
    # ✅ MFA Support Fields
    is_mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=64, blank=True, null=True)

    def generate_mfa_secret(self):
        """
        Generates and stores a new MFA secret key for the user.
        """
        self.mfa_secret = pyotp.random_base32()
        self.is_mfa_enabled = True
        self.save()
        return self.mfa_secret

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        roles = ", ".join(self.roles.values_list(
            "name", flat=True)) if self.roles.exists() else "No Roles"
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
