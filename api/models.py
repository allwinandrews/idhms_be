from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.crypto import get_random_string  # For generating unique baby IDs
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers


class CustomUserManager(BaseUserManager):
    """
    Custom user manager to handle user creation using email as the primary identifier.
    """

    def create_user(self, email, password=None, roles=None, **extra_fields):
        """
        Create and return a regular user with an email, password, and optional roles.
        """
        if not email:
            raise ValueError("The Email field is required")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)
        # extra_fields.setdefault("username", None)  # Handle absence of username

        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        # Assign roles if provided
        if roles:
            user.roles.set(roles)

        return user

    def create_superuser(self, email, password=None, roles=None, **extra_fields):
        """
        Create and return a superuser with an email, password, and optional roles.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        roles = roles or ["Admin"]  # Default role for superusers
        return self.create_user(email, password, roles=roles, **extra_fields)


class Role(models.Model):
    """
    Role model for managing user roles.
    """

    name = models.CharField(
        max_length=20,
        unique=True,
    )

    def __str__(self):
        return self.name


class User(AbstractUser):
    """
    Custom User model that supports multiple roles.
    """

    ROLE_CHOICES = [
        ("Admin", "Admin"),
        ("Dentist", "Dentist"),
        ("Receptionist", "Receptionist"),
        ("Patient", "Patient"),
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
    email = models.EmailField(unique=True)  # Use email as the unique identifier
    roles = models.ManyToManyField(
        Role,
        related_name="users",
        blank=True,
        help_text=_("Assign one or more roles to the user."),
    )
    dob = models.DateField(blank=True, null=True)
    contact_info = models.CharField(max_length=15, blank=True, null=True)
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

    def __str__(self):
        return f"{self.email} ({', '.join(self.roles.values_list('name', flat=True))})"


class Appointment(models.Model):
    STATUS_CHOICES = [
        ("Scheduled", "Scheduled"),
        ("Completed", "Completed"),
        ("Cancelled", "Cancelled"),
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
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="Scheduled"
    )

    def clean(self):
        """
        Custom validation to ensure the correct roles for patient and dentist.
        """
        if not self.patient.roles.filter(name="Patient").exists():
            raise serializers.ValidationError(
                f"User {self.patient.email} must have the 'Patient' role."
            )
        if self.dentist and not self.dentist.roles.filter(name="Dentist").exists():
            raise serializers.ValidationError(
                f"User {self.dentist.email} must have the 'Dentist' role."
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
        if not self.patient.roles.filter(name="Patient").exists():
            raise serializers.ValidationError(
                f"User {self.patient.email} must have the 'Patient' role."
            )

    def __str__(self):
        return f"Billing for {self.patient.first_name} {self.patient.last_name} - {self.amount}"
