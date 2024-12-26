import pytest
from rest_framework import status


@pytest.mark.django_db
def test_register_user(api_client):
    """
    Test user registration with valid and invalid inputs.
    """
    # Positive: Valid registration
    response = api_client.post(
        "/api/register/",
        {
            "email": "test@example.com",
            "password": "StrongPassword123!",
            "role": "Patient",
            "dob": "1990-01-01",
            "contact_info": "+1234567890",
            "first_name": "Test",
            "last_name": "User",
            "gender": "Male",
        },
    )
    print(response.data)
    assert response.status_code == status.HTTP_201_CREATED

    # Negative: Missing fields
    response = api_client.post(
        "/api/register/",
        {"email": "missingfields@example.com", "password": "password123"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "dob" in response.data
    assert "contact_info" in response.data

    # Negative: Duplicate email
    response = api_client.post(
        "/api/register/",
        {
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "password": "StrongPassword123!",
            "role": "Patient",
            "dob": "1990-01-01",
            "contact_info": "+1234567890",
        },
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "email" in response.data


@pytest.mark.django_db
def test_login_user(api_client, create_user):
    """
    Test user login with valid and invalid credentials.
    """
    # Create a test user
    create_user(email="validuser@example.com", password="testpassword", role="Patient")

    # Positive: Valid login
    response = api_client.post(
        "/api/login/", {"email": "validuser@example.com", "password": "testpassword"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert "access" in response.data
    assert "refresh" in response.data

    # Negative: Invalid password
    response = api_client.post(
        "/api/login/", {"email": "validuser@example.com", "password": "wrongpassword"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert (
        response.data["detail"] == "No active account found with the given credentials"
    )

    # Negative: Unregistered email
    response = api_client.post(
        "/api/login/", {"email": "unregistered@example.com", "password": "password123"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
def test_token_refresh(api_client, create_user):
    """
    Test refreshing JWT token with valid and invalid refresh tokens.
    """
    # Create a test user and login to get refresh token
    create_user(
        email="refreshuser@example.com", password="testpassword", role="Patient"
    )
    response = api_client.post(
        "/api/login/", {"email": "refreshuser@example.com", "password": "testpassword"}
    )
    refresh_token = response.data["refresh"]

    # Positive: Valid refresh token
    response = api_client.post("/api/login/refresh/", {"refresh": refresh_token})
    assert response.status_code == status.HTTP_200_OK
    assert "access" in response.data

    # Negative: Invalid refresh token
    response = api_client.post("/api/login/refresh/", {"refresh": "invalidtoken"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data
