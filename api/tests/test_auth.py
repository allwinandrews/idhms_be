import pyotp
import pytest
from rest_framework import status
from api.models import Role
from rest_framework_simplejwt.tokens import RefreshToken


@pytest.mark.django_db
def test_register_user(api_client):
    """
    Test user registration with valid and invalid inputs.
    """
    print("roles:", Role.objects.all().values_list("name", flat=True))

    # ✅ Positive: Valid registration
    response = api_client.post(
        "/api/register/",
        {
            "email": "test@example.com",
            "password": "StrongPassword123!",
            "roles": ["patient"],
            "dob": "1990-01-01",
            "contact_info": "+1234567890",
            "first_name": "Test",
            "last_name": "User",
            "gender": "Male",
            "blood_group": "O+",
        },
    )
    assert response.status_code == status.HTTP_201_CREATED

    # ❌ Negative: Missing required fields
    response = api_client.post(
        "/api/register/",
        {"email": "missingfields@example.com", "password": "password123"},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert all(field in response.data for field in [
               "first_name", "last_name", "dob", "gender", "blood_group"])

    # ❌ Negative: Duplicate email registration
    response = api_client.post(
        "/api/register/",
        {
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "password": "StrongPassword123!",
            "roles": ["patient"],
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
    create_user(email="validuser@example.com",
                password="testpassword", roles=["patient"])

    # ✅ Attempt to log in
    response = api_client.post(
        "/api/login/", {"email": "validuser@example.com",
                        "password": "testpassword"}
    )

    print("Login Response Data:", response.data)  # 🔍 Debugging print
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
def test_enable_mfa(api_client, create_user):
    """
    Test enabling MFA for a user.
    """
    user = create_user(email="mfauser@example.com",
                       password="securepass", is_mfa_enabled=False)

    # ✅ Positive: Enable MFA
    api_client.force_authenticate(user=user)
    response = api_client.post("/api/auth/mfa/enable/")
    assert response.status_code == status.HTTP_200_OK
    assert "qr_code_url" in response.data
    assert user.is_mfa_enabled is True


@pytest.mark.django_db
def test_verify_mfa(api_client, create_user):
    """
    Test verifying MFA code during login.
    """
    user = create_user(email="mfauser@example.com",
                       password="securepass", is_mfa_enabled=True)

    # ✅ Ensure MFA is enabled and secret is generated
    user.generate_mfa_secret()
    user.refresh_from_db()

    print("MFA Secret for User:", user.mfa_secret)  # Debugging step

    assert user.mfa_secret is not None, "MFA Secret should not be None"

    # ✅ Generate valid MFA code
    totp = pyotp.TOTP(user.mfa_secret)
    valid_mfa_code = totp.now()

    print("Generated MFA Code:", valid_mfa_code)  # Debugging step

    # ✅ Positive: Correct MFA code with email included
    response = api_client.post(
        "/api/auth/mfa/verify/",
        {"email": "mfauser@example.com", "mfa_code": valid_mfa_code},
        format="json"  # ✅ Ensures correct content type
    )

    print("MFA Verification Response:", response.data)  # Debugging step
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.data["message"] == "MFA verification successful."


@pytest.mark.django_db
def test_bulk_register_users_non_admin(api_client, create_user):
    """
    Ensure non-admin users cannot access bulk registration.
    """
    patient_user = create_user(
        email="patient@example.com", password="patient_pass", roles=["patient"])
    api_client.force_authenticate(user=patient_user)

    valid_payload = {
        "users": [
            {
                "email": "user1@example.com",
                "password": "Password123!",
                "roles": ["patient"],
                "dob": "1990-01-01",
                "contact_info": "+1234567890",
                "first_name": "User1",
                "last_name": "Example",
                "gender": "Male",
                "blood_group": "O+",
            }
        ]
    }

    # ❌ Negative: Non-admin users should not access bulk registration
    response = api_client.post(
        "/api/register/bulk/", valid_payload, format="json")
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_register_dependent_with_inline_guardian(api_client, create_user):
    """
    ✅ Register a dependent user along with inline guardian creation.
    """
    guardian_user = create_user(
        email="guardian@example.com",
        password="guardianpass",
        roles=["patient"],
        dob="1980-05-20",  # ✅ Ensure guardian is over 18
    )

    response = api_client.post(
        "/api/register/",
        {
            "email": "dependent@example.com",
            "password": "dependentpass",
            "roles": ["patient"],
            "dob": "2020-01-01",  # ✅ Dependent (child) DOB
            "first_name": "Dependent",
            "last_name": "User",
            "gender": "Male",
            "blood_group": "O+",
            "guardian": guardian_user.id,  # ✅ Link to existing guardian
        },
    )

    response_data = response.json()
    print("📌 Response Data:", response_data)  # Debugging Output

    assert response.status_code == status.HTTP_201_CREATED
    assert response_data["user_type"] == "Dependent"
    assert response_data["guardian"]["id"] == guardian_user.id


@pytest.mark.django_db
def test_token_refresh(api_client, create_user):
    """
    ✅ Ensure a valid refresh token correctly issues a new access token.
    """
    user = create_user(email="refreshuser@example.com", password="securepass")

    # ✅ Step 1: Log in to get refresh token in cookies
    response = api_client.post(
        "/api/login/", {"email": user.email, "password": "securepass"})
    assert response.status_code == status.HTTP_200_OK

    # ✅ Step 2: Extract refresh token from cookies
    refresh_token = response.cookies.get("refresh_token")
    assert refresh_token is not None  # Ensure the refresh token exists

    # ✅ Step 3: Use the refresh token to get a new access token
    # Set refresh token in cookies
    api_client.cookies["refresh_token"] = refresh_token.value
    refresh_response = api_client.post("/api/login/refresh/")

    # ✅ Step 4: Assertions
    assert refresh_response.status_code == status.HTTP_200_OK
    # Ensure a new access token is issued
    assert "access_token" in refresh_response.cookies
    assert refresh_response.data["message"] == "Token refreshed successfully!"


@pytest.mark.django_db
def test_token_refresh_invalid_token(api_client):
    """
    ❌ Ensure invalid or missing refresh tokens are rejected.
    """

    # ✅ Step 1: Attempt to refresh without any token
    response = api_client.post("/api/login/refresh/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.data["detail"] == "Refresh token is missing."

    # ✅ Step 2: Attempt to refresh with an invalid token
    api_client.cookies["refresh_token"] = "invalid_token"
    response_invalid = api_client.post("/api/login/refresh/")

    assert response_invalid.status_code == status.HTTP_401_UNAUTHORIZED
    assert response_invalid.data["detail"] in [
        "Invalid refresh token.", "Token is invalid or expired"
    ]


@pytest.mark.django_db
def test_logout_user(api_client, create_user):
    """
    ✅ Ensure logout clears cookies and blacklists refresh token.
    """

    # ✅ Step 1: Create and log in a user
    user = create_user(email="logoutuser@example.com",
                       password="securepass", roles=["patient"])

    response_login = api_client.post(
        "/api/login/", {"email": "logoutuser@example.com",
                        "password": "securepass"}
    )

    assert response_login.status_code == status.HTTP_200_OK
    assert "access_token" in response_login.cookies
    assert "refresh_token" in response_login.cookies

    # ✅ Step 2: Attempt Logout
    api_client.force_authenticate(user=user)
    response_logout = api_client.post("/api/logout/")

    assert response_logout.status_code == status.HTTP_200_OK
    assert response_logout.data["message"] == "Logout successful!"

    # ✅ Step 3: Ensure cookies are properly cleared
    assert response_logout.cookies["access_token"].value == ""
    assert response_logout.cookies["refresh_token"].value == ""

    # ✅ Step 4: Try using blacklisted refresh token (Negative Case)
    api_client.cookies["refresh_token"] = response_login.cookies["refresh_token"]

    response_refresh = api_client.post("/api/login/refresh/")

    # ✅ Ensure token refresh is blocked if blacklisting works
    if hasattr(RefreshToken, "blacklist"):
        assert response_refresh.status_code == status.HTTP_401_UNAUTHORIZED
