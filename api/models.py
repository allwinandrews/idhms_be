from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager


class CustomUserManager(BaseUserManager):
    """
    Custom user manager to handle user creation using email as the primary identifier.
    """

    def create_user(self, email, password=None, **extra_fields):
        """
        Create and return a regular user with an email and password.
        """
        if not email:
            raise ValueError("The Email field is required")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and return a superuser with an email and password.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """
    Custom User model that uses email as the primary identifier.
    """

    ROLE_CHOICES = [
        ("Admin", "Admin"),
        ("Dentist", "Dentist"),
        ("Receptionist", "Receptionist"),
        ("Patient", "Patient"),
    ]

    username = None  # Remove the username field
    email = models.EmailField(unique=True)  # Make email the unique field
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default="Patient",
    )
    dob = models.DateField(blank=True, null=True)  # Patient-specific field
    contact_info = models.CharField(max_length=15, blank=True, null=True)
    gender = models.CharField(
        max_length=10,
        choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")],
        blank=True,
        null=True,
    )

    USERNAME_FIELD = "email"  # Use email as the unique identifier
    REQUIRED_FIELDS = ["role"]  # Fields required when creating a superuser

    objects = CustomUserManager()

    def __str__(self):
        return self.email


class Appointment(models.Model):
    STATUS_CHOICES = [
        ("Scheduled", "Scheduled"),
        ("Completed", "Completed"),
        ("Cancelled", "Cancelled"),
    ]

    patient = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="patient_appointments",  # For appointments linked to a patient
        limit_choices_to={"role": "Patient"},
    )
    dentist = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dentist_appointments",  # For appointments linked to a dentist
        limit_choices_to={"role": "Dentist"},
    )
    appointment_date = models.DateTimeField()
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="Scheduled"
    )

    def __str__(self):
        return f"Appointment for {self.patient.first_name} {self.patient.last_name} on {self.appointment_date}"


class Billing(models.Model):
    patient = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="billings",
        limit_choices_to={"role": "Patient"},
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    billing_date = models.DateField()

    def __str__(self):
        return f"Billing for {self.patient.first_name} {self.patient.last_name} - {self.amount}"
