import pytest
from rest_framework import status


@pytest.mark.django_db
def test_admin_list_users(api_client, create_user, admin_token):
    """
    Test that an Admin can list all users and filter by role.
    """
    # Create test users
    create_user(email="dentist@example.com", password="password123", role="Dentist")
    create_user(email="patient@example.com", password="password123", role="Patient")

    # Admin lists all users
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token}")
    response = api_client.get("/api/users/")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) >= 2  # Admin sees all users

    # Admin filters users by role
    response = api_client.get("/api/users/", {"role": "Dentist"})
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) == 1  # Only dentists returned
    assert response.data[0]["email"] == "dentist@example.com"


@pytest.mark.django_db
def test_admin_retrieve_user(api_client, create_user, admin_token):
    """
    Test that an Admin can retrieve a specific user's details.
    """
    user = create_user(
        email="patient@example.com", password="password123", role="Patient"
    )

    # Admin retrieves the user's details
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token}")
    response = api_client.get(f"/api/users/{user.id}/")
    assert response.status_code == status.HTTP_200_OK
    assert response.data["email"] == "patient@example.com"


@pytest.mark.django_db
def test_admin_update_user(api_client, create_user, admin_token):
    """
    Test that an Admin can update a specific user's details, including the role.
    """
    user = create_user(
        email="receptionist@example.com", password="password123", role="Receptionist"
    )

    # Admin updates the user's details
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token}")
    response = api_client.put(
        f"/api/users/{user.id}/",
        {
            "email": "receptionist@example.com",
            "first_name": "Updated",
            "last_name": "User",
            "role": "Patient",  # Update the role to Patient
        },
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.data["first_name"] == "Updated"
    assert response.data["role"] == "Patient"  # Confirm the role update


@pytest.mark.django_db
def test_admin_delete_user(api_client, create_user, admin_token):
    """
    Test that an Admin can delete a specific user.
    """
    user = create_user(
        email="deletethis@example.com", password="password123", role="Dentist"
    )

    # Admin deletes the user
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token}")
    response = api_client.delete(f"/api/users/{user.id}/")
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not response.data  # No content returned


@pytest.mark.django_db
def test_non_admin_access_users(
    api_client, create_user, receptionist_token, patient_token
):
    """
    Test that non-Admin roles cannot access user management endpoints.
    """
    # Receptionist tries to list users
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {receptionist_token}")
    response = api_client.get("/api/users/")
    assert response.status_code == status.HTTP_403_FORBIDDEN

    # Patient tries to retrieve a specific user
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {patient_token}")
    response = api_client.get("/api/users/1/")
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_no_token_access_users(api_client):
    """
    Test accessing user management endpoints without a token.
    """
    # Attempt to list users without a token
    response = api_client.get("/api/users/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    # Attempt to retrieve a specific user without a token
    response = api_client.get("/api/users/1/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
