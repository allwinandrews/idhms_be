import pytest
from rest_framework.test import APIClient


@pytest.fixture
def api_client():
    """
    Fixture to create an API client instance.
    """
    return APIClient()


@pytest.mark.django_db
def test_register_user(api_client):
    """
    Test user registration with valid and invalid inputs.
    """
    # Valid registration
    response = api_client.post(
        "/api/register/",
        {
            "first_name": "John",
            "last_name": "Doe",
            "email": "johndoe@example.com",
            "password": "strongpassword123",
            "role": "Patient",
            "phone_number": "+1234567890",
            "dob": "1990-05-15",
        },
    )
    assert response.status_code == 201
    assert response.data["message"] == "User registered successfully!"

    # Invalid registration: Missing email
    response = api_client.post(
        "/api/register/",
        {
            "first_name": "Jane",
            "last_name": "Doe",
            "password": "weakpassword",
            "role": "Patient",
        },
    )
    assert response.status_code == 400
    assert "email" in response.data


@pytest.mark.django_db
def test_login_user(api_client, create_user):
    """
    Test user login with valid and invalid credentials.
    """
    # Create a test user
    create_user(email="test@example.com", password="test_password", role="Patient")

    # Valid login
    response = api_client.post(
        "/api/login/", {"email": "test@example.com", "password": "test_password"}
    )
    assert response.status_code == 200
    assert "access" in response.data
    assert "refresh" in response.data
    assert response.data["role"] == "Patient"

    # Invalid login: Incorrect password
    response = api_client.post(
        "/api/login/", {"email": "test@example.com", "password": "wrong_password"}
    )
    assert response.status_code == 401
    assert (
        response.data["detail"] == "No active account found with the given credentials"
    )

    # Invalid login: Non-existent email
    response = api_client.post(
        "/api/login/", {"email": "nonexistent@example.com", "password": "password123"}
    )
    assert response.status_code == 401
    assert (
        response.data["detail"] == "No active account found with the given credentials"
    )


@pytest.mark.django_db
def test_token_refresh(api_client, create_user):
    """
    Test JWT token refresh functionality.
    """
    # Create a test user with email-based authentication
    create_user(email="refresh_user@example.com", password="refresh_password", role="Patient")

    # Get tokens via login
    response = api_client.post(
        "/api/login/", {"email": "refresh_user@example.com", "password": "refresh_password"}
    )
    assert response.status_code == 200
    refresh_token = response.data["refresh"]

    # Valid token refresh
    response = api_client.post("/api/login/refresh/", {"refresh": refresh_token})
    assert response.status_code == 200
    assert "access" in response.data

    # Invalid token refresh
    response = api_client.post("/api/login/refresh/", {"refresh": "invalid_refresh_token"})
    assert response.status_code == 401
    assert "detail" in response.data
