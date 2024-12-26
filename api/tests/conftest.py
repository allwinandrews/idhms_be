import pytest
from rest_framework.test import APIClient
from api.models import Appointment
from django.utils.timezone import make_aware
from datetime import datetime

from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.fixture
def api_client():
    """
    Fixture to create an API client instance.
    """
    return APIClient()


@pytest.fixture
def create_user():
    """
    Fixture to create users with email and role.
    """

    def _create_user(email, password, role):
        return User.objects.create_user(email=email, password=password, role=role)

    return _create_user


@pytest.fixture
def admin_token(api_client, create_user):
    """
    Fixture to generate an admin user's JWT token.
    """
    create_user(email="admin_user@example.com", password="admin_pass", role="Admin")
    response = api_client.post(
        "/api/login/", {"email": "admin_user@example.com", "password": "admin_pass"}
    )
    return response.data["access"]


@pytest.fixture
def patient_token(api_client, create_user):
    """
    Fixture to generate a patient's JWT token.
    """
    create_user(
        email="patient_user@example.com", password="patient_pass", role="Patient"
    )
    response = api_client.post(
        "/api/login/", {"email": "patient_user@example.com", "password": "patient_pass"}
    )
    return response.data["access"]


@pytest.fixture
def dentist_token(api_client, create_user):
    """
    Fixture to generate a dentist's JWT token.
    """
    create_user(
        email="dentist_user@example.com", password="dentist_pass", role="Dentist"
    )
    response = api_client.post(
        "/api/login/", {"email": "dentist_user@example.com", "password": "dentist_pass"}
    )
    return response.data["access"]


@pytest.fixture
def receptionist_token(api_client, create_user):
    """
    Fixture to generate a receptionist's JWT token.
    """
    create_user(
        email="receptionist_user@example.com",
        password="receptionist_pass",
        role="Receptionist",
    )
    response = api_client.post(
        "/api/login/",
        {"email": "receptionist_user@example.com", "password": "receptionist_pass"},
    )
    return response.data["access"]


@pytest.fixture
def create_patients():
    """
    Fixture to create multiple patients for testing.
    """
    patients = [
        User.objects.create_user(
            email=f"patient{i}@example.com",
            password="password123",
            role="Patient",
            first_name=f"Patient{i}",
            last_name="Test",
            contact_info=f"+123456789{i}",
            dob="1990-01-01",
            gender="Male" if i % 2 == 0 else "Female",
        )
        for i in range(1, 6)
    ]
    return patients


@pytest.fixture
def create_appointments(create_user):
    """
    Fixture to create multiple test appointments.
    """
    patient = create_user(
        email="patient@example.com", password="password123", role="Patient"
    )
    dentist = create_user(
        email="dentist@example.com", password="password123", role="Dentist"
    )
    return [
        Appointment.objects.create(
            patient=patient,
            dentist=dentist,
            appointment_date=make_aware(datetime(2024, 12, 25, 10, 0, 0)),  # Fix here
            # appointment_date="2024-12-25 10:00:00",
            status="Scheduled",
        )
        for _ in range(5)
    ]
