import pytest
from rest_framework import status
from api.models import Role


@pytest.mark.django_db
def test_admin_list_users(api_client, create_user):
    """
    Test that an Admin can list all users and filter by role.
    """
    # Create test users
    create_user(email="dentist@example.com", password="password123", roles=["Dentist"])
    create_user(email="patient@example.com", password="password123", roles=["Patient"])

    # Admin login
    create_user(email="admin@example.com", password="admin123", roles=["Admin"])
    response = api_client.post(
        "/api/login/", {"email": "admin@example.com", "password": "admin123"}
    )
    assert response.status_code == 200
    admin_token = response.cookies.get("access_token")
    print("Admin Token (Cookie):", admin_token)
    assert admin_token is not None  # Ensure the token is retrieved

    # Admin access to list all users
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token.value}")
    response = api_client.get("/api/users/")
    print("Response Data:", response.data)
    assert response.status_code == 200
    assert len(response.data) >= 2  # Ensure users are listed

    # Filter users by role (e.g., Dentist)
    response = api_client.get("/api/users/?role=Dentist")
    assert response.status_code == 200
    assert len(response.data) == 1  # Only one user with the Dentist role
    assert response.data[0]["email"] == "dentist@example.com"


@pytest.mark.django_db
def test_admin_update_user(api_client, create_user):
    """
    Test that an Admin can update a specific user's details, including the role.
    """
    # Step 1: Create a receptionist user
    user = create_user(
        email="receptionist@example.com", password="password123", roles=["Receptionist"]
    )

    # Step 2: Create an admin user and log in
    create_user(email="admin@example.com", password="admin_pass", roles=["Admin"])
    response = api_client.post(
        "/api/login/", {"email": "admin@example.com", "password": "admin_pass"}
    )
    assert response.status_code == 200  # Ensure login is successful

    admin_token = response.cookies.get("access_token")
    assert admin_token is not None  # Ensure the token exists
    admin_token_value = admin_token.value  # Extract only the token value
    # print("Admin Token Value:", admin_token_value)

    # Step 3: Admin updates the user's details
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token_value}")
    # print("Headers:", api_client._credentials)

    response = api_client.put(
        f"/api/users/{user.id}/",
        {
            "first_name": "Updated",
            "last_name": "User",
            "roles": ["Patient"],  # Correct JSON array
        },
        format="json",
    )
    print("Response data:", response.data)
    assert response.status_code == 200  # Ensure the update is successful
    assert response.data["first_name"] == "Updated"
    assert response.data["last_name"] == "User"
    assert "Patient" in response.data["roles"]


@pytest.mark.django_db
def test_admin_delete_user(api_client, create_user):
    """
    Test that an Admin can delete a specific user.
    """
    # Step 1: Create the user to be deleted
    user = create_user(
        email="deletethis@example.com", password="password123", roles=["Dentist"]
    )

    # Step 2: Create an admin user and log in
    create_user(email="admin@example.com", password="admin_pass", roles=["Admin"])
    response = api_client.post(
        "/api/login/", {"email": "admin@example.com", "password": "admin_pass"}
    )
    assert response.status_code == 200  # Ensure login is successful
    admin_token = response.cookies.get("access_token")
    assert admin_token is not None  # Ensure the token exists

    # Step 3: Admin deletes the user
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token.value}")
    response = api_client.delete(f"/api/users/{user.id}/")
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not response.data  # No content returned


@pytest.mark.django_db
def test_non_admin_access_users(api_client, create_user):
    """
    Test that non-admin users cannot access the user management endpoints.
    """
    # Step 1: Create a non-admin user
    non_admin_user = create_user(
        email="non_admin_user@example.com",
        password="password123",
        roles=["Patient"],
    )

    # Step 2: Log in as the non-admin user
    response = api_client.post(
        "/api/login/",
        {"email": "non_admin_user@example.com", "password": "password123"},
    )
    assert response.status_code == 200
    non_admin_token = response.cookies.get("access_token")
    assert non_admin_token is not None  # Ensure the token exists

    # Step 3: Attempt to access user management endpoints as a non-admin user
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {non_admin_token.value}")

    # Try to list all users
    response = api_client.get("/api/users/")
    assert response.status_code == 403  # Non-admin users should not have access

    # Try to retrieve a specific user
    response = api_client.get("/api/users/1/")
    assert response.status_code == 403  # Non-admin users should not have access

    # Try to update a user
    response = api_client.put(
        "/api/users/1/",
        {
            "first_name": "Updated",
            "last_name": "User",
            "roles": ["Patient"],  # Attempt to change role
        },
    )
    assert response.status_code == 403  # Non-admin users should not have access

    # Try to delete a user
    response = api_client.delete("/api/users/1/")
    assert response.status_code == 403  # Non-admin users should not have access


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


@pytest.mark.django_db
@pytest.mark.django_db
def test_filter_users_by_role(api_client, create_user):
    """
    Test filtering users by role using query parameters.
    """
    # Set up users with different roles
    create_user(email="dentist1@example.com", password="password123", roles=["Dentist"])
    create_user(
        email="receptionist1@example.com",
        password="password123",
        roles=["Receptionist"],
    )
    create_user(email="patient1@example.com", password="password123", roles=["Patient"])

    # Step 1: Create and login as admin
    create_user(email="admin@example.com", password="admin_pass", roles=["Admin"])
    response = api_client.post(
        "/api/login/", {"email": "admin@example.com", "password": "admin_pass"}
    )
    assert response.status_code == 200
    admin_token = response.cookies.get("access_token")
    assert admin_token is not None  # Ensure the token is present

    # Authenticate as admin
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token.value}")

    # Step 2: Test with no query parameter (list all non-admin users)
    response = api_client.get("/api/users/")
    assert response.status_code == status.HTTP_200_OK

    # Exclude admin users manually in the test
    non_admin_users = [user for user in response.data if "Admin" not in user["roles"]]
    assert len(non_admin_users) == 3

    # Step 3: Test filtering by role
    response = api_client.get("/api/users/?role=Dentist")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) == 1
    assert response.data[0]["email"] == "dentist1@example.com"

    response = api_client.get("/api/users/?role=Receptionist")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) == 1
    assert response.data[0]["email"] == "receptionist1@example.com"

    response = api_client.get("/api/users/?role=Patient")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) == 1
    assert response.data[0]["email"] == "patient1@example.com"
