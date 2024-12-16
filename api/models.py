from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    """
    Custom User model with role-based access and additional fields for patients.
    """

    ROLE_CHOICES = [
        ("Admin", "Admin"),
        ("Dentist", "Dentist"),
        ("Receptionist", "Receptionist"),
        ("Patient", "Patient"),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="Patient")
    dob = models.DateField(blank=True, null=True)  # Patient-specific field
    contact_info = models.CharField(
        max_length=15, blank=True, null=True
    )  # Phone number
    gender = models.CharField(
        max_length=10,
        choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")],
        blank=True,
        null=True,
    )


class Patient(models.Model):
    """
    Represents a patient in the dental management system.

    Attributes:
        name (str): Full name of the patient.
        contact_info (str): Contact details (e.g., phone, email).
        dob (Date): Date of birth.
        gender (str): Gender of the patient (Male, Female, Other).
    """

    GENDER_CHOICES = [
        ("Male", "Male"),
        ("Female", "Female"),
        ("Other", "Other"),
    ]
    name = models.CharField(max_length=100)
    contact_info = models.CharField(max_length=255, blank=True, null=True)
    dob = models.DateField(blank=True, null=True)
    gender = models.CharField(
        max_length=10, choices=GENDER_CHOICES, blank=True, null=True
    )

    def __str__(self):
        return self.name


class Appointment(models.Model):
    """
    Represents an appointment in the dental management system.

    Attributes:
        patient (ForeignKey): Link to the patient.
        dentist (ForeignKey): Link to the user (dentist role).
        appointment_date (DateTime): Date and time of the appointment.
        status (str): Status of the appointment (Scheduled, Completed, Cancelled).
    """

    STATUS_CHOICES = [
        ("Scheduled", "Scheduled"),
        ("Completed", "Completed"),
        ("Cancelled", "Cancelled"),
    ]
    patient = models.ForeignKey(
        Patient, on_delete=models.CASCADE, related_name="appointments"
    )
    dentist = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="appointments",
    )  # Link to User model
    appointment_date = models.DateTimeField()
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="Scheduled"
    )

    def __str__(self):
        return f"Appointment for {self.patient.name} on {self.appointment_date}"


class Billing(models.Model):
    """
    Represents a billing record in the dental management system.

    Attributes:
        patient (ForeignKey): Link to the patient.
        amount (float): Amount billed.
        billing_date (Date): Date of the billing.
    """

    patient = models.ForeignKey(
        Patient, on_delete=models.CASCADE, related_name="billings"
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    billing_date = models.DateField()

    def __str__(self):
        return f"Billing: {self.patient.name} - {self.amount}"
