import pytest
from rest_framework import status


@pytest.mark.django_db
def test_admin_access(api_client, create_user, admin_token):
    """
    Test that an admin user can access the admin-specific endpoint.
    """
    api_client.cookies["access_token"] = admin_token.value
    response = api_client.get("/api/admin/")
    assert response.status_code == status.HTTP_200_OK
    assert response.data["message"] == "Welcome, admin!"


@pytest.mark.django_db
def test_non_admin_access(api_client, create_user, receptionist_token, patient_token):
    """
    Test that non-admin roles cannot access the admin endpoint.
    """
    # receptionist tries to access the admin endpoint
    api_client.cookies["access_token"] = receptionist_token.value
    response = api_client.get("/api/admin/")
    assert response.status_code == status.HTTP_403_FORBIDDEN

    # patient tries to access the admin endpoint
    api_client.cookies["access_token"] = patient_token.value
    response = api_client.get("/api/admin/")
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_no_token_access(api_client):
    """
    Test accessing the admin endpoint without a token.
    """
    response = api_client.get("/api/admin/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.data
    assert response.data["detail"] == "Authentication credentials were not provided."
