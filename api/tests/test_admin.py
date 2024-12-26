import pytest
from rest_framework import status


@pytest.mark.django_db
def test_admin_access(api_client, create_user, admin_token):
    """
    Test that an Admin user can access the Admin-specific endpoint.
    """
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token}")
    response = api_client.get("/api/admin/")
    assert response.status_code == status.HTTP_200_OK
    assert response.data["message"] == "Welcome, Admin!"


@pytest.mark.django_db
def test_non_admin_access(api_client, create_user, receptionist_token, patient_token):
    """
    Test that non-Admin roles cannot access the Admin endpoint.
    """
    # Receptionist tries to access the Admin endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {receptionist_token}")
    response = api_client.get("/api/admin/")
    assert response.status_code == status.HTTP_403_FORBIDDEN

    # Patient tries to access the Admin endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {patient_token}")
    response = api_client.get("/api/admin/")
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_no_token_access(api_client):
    """
    Test accessing the Admin endpoint without a token.
    """
    response = api_client.get("/api/admin/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data
    assert response.data["detail"] == "Authentication credentials were not provided."
