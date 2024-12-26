import pytest
from rest_framework import status


@pytest.mark.django_db
def test_secure_access_with_valid_token(api_client, create_user):
    """
    Test accessing the secure endpoint with a valid token.
    """
    # Create a test user and log in
    user = create_user(
        email="secure_user@example.com", password="password123", role="Patient"
    )
    response = api_client.post(
        "/api/login/", {"email": user.email, "password": "password123"}
    )
    access_token = response.data["access"]

    # Access the secure endpoint with a valid token
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    response = api_client.get("/api/secure/")
    assert response.status_code == status.HTTP_200_OK
    assert response.data["message"] == "This is a secure view!"


@pytest.mark.django_db
def test_secure_access_without_token(api_client):
    """
    Test accessing the secure endpoint without a token.
    """
    response = api_client.get("/api/secure/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data
    assert response.data["detail"] == "Authentication credentials were not provided."


@pytest.mark.django_db
def test_secure_access_with_invalid_token(api_client):
    """
    Test accessing the secure endpoint with an invalid token.
    """
    api_client.credentials(HTTP_AUTHORIZATION="Bearer invalid_token")
    response = api_client.get("/api/secure/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data
    assert response.data["detail"] == "Given token not valid for any token type"
