import pytest
from rest_framework import status
from api.models import Role


@pytest.mark.django_db
def test_register_user(api_client):
    """
    Test user registration with valid and invalid inputs.
    """
    print("roles:", Role.objects.all().values_list("name", flat=True))

    # Positive: Valid registration
    response = api_client.post(
        "/api/register/",
        {
            "email": "test@example.com",
            "password": "StrongPassword123!",
            "roles": ["Patient"],
            "dob": "1990-01-01",
            "contact_info": "+1234567890",
            "first_name": "Test",
            "last_name": "User",
            "gender": "Male",
            "blood_group": "O+",
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
    assert "first_name" in response.data
    assert "last_name" in response.data
    assert "dob" in response.data
    assert "gender" in response.data
    assert "blood_group" in response.data

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
def test_register_dependent_with_inline_guardian(api_client, setup_roles):
    """
    Test registering a Dependent with inline guardian creation.
    """
    response = api_client.post(
        "/api/register/",
        {
            "first_name": "Dependent",
            "last_name": "Smith",
            "roles": ["Patient"],
            "dob": "2024-01-01",
            "gender": "Male",
            "blood_group": "O+",
            "guardian_data": {
                "first_name": "John",
                "last_name": "Doe",
                "email": "johndoe@example.com",
                "password": "SecurePassword123",
                "contact_info": "+1234567890",
                "roles": ["Patient"],
                "dob": "1990-01-01",  # Added dob
                "gender": "Male",  # Added gender
                "blood_group": "O+",  # Added blood_group
            },
        },
        format="json",  # Explicitly specify JSON format
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert "User registered successfully!" in response.data["message"]
    assert response.data["user_type"] == "Dependent"
    assert response.data["guardian"]["email"] == "johndoe@example.com"


@pytest.mark.django_db
def test_login_user(api_client, create_user):
    """
    Test user login with valid and invalid credentials.
    """
    # Create a test user
    create_user(
        email="validuser@example.com", password="testpassword", roles=["Patient"]
    )

    # Positive: Valid login
    response = api_client.post(
        "/api/login/", {"email": "validuser@example.com", "password": "testpassword"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.cookies.get("access_token") is not None
    assert response.cookies.get("refresh_token") is not None

    # Negative: Invalid password
    response = api_client.post(
        "/api/login/", {"email": "validuser@example.com", "password": "wrongpassword"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert (
        response.data["detail"] == "No active account found with the given credentials."
    )

    # Negative: Unregistered email
    response = api_client.post(
        "/api/login/", {"email": "unregistered@example.com", "password": "password123"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert (
        response.data["detail"] == "No active account found with the given credentials."
    )


@pytest.mark.django_db
def test_token_refresh(api_client, create_user):
    """
    Test refreshing JWT token with valid and invalid refresh tokens.
    """
    # Create a test user and login to get refresh token
    create_user(
        email="refreshuser@example.com", password="testpassword", roles=["Patient"]
    )
    response = api_client.post(
        "/api/login/", {"email": "refreshuser@example.com", "password": "testpassword"}
    )
    assert response.status_code == status.HTTP_200_OK

    refresh_token = response.cookies.get("refresh_token")
    print("Refresh token obtained:", refresh_token)

    # Positive: Valid refresh token
    response = api_client.post(
        "/api/login/refresh/", {}, cookies={"refresh_token": refresh_token.value}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.cookies.get("access_token") is not None


@pytest.mark.django_db
def test_token_refresh_invalid_token(api_client):
    """
    Test token refresh with an invalid token.
    """
    # Attempt to refresh with a completely invalid token
    api_client.cookies["refresh_token"] = "invalid.refresh.token"
    # print("Test client cookies before request:", api_client.cookies)
    response = api_client.post("/api/login/refresh/", {})
    # print("Response cookies:", response.cookies)
    # print("Response for invalid token:", response.data)

    # Ensure the response returns a 401 status with the correct error message
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.data["detail"] == "Invalid refresh token."
