import pytest
from rest_framework.test import APIClient
from api.models import User


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
