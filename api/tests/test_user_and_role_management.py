import pytest
from rest_framework import status
from api.models import User, Role


@pytest.mark.django_db
def test_admin_list_users(api_client, create_user):
    """
    Test that an admin can list all users and filter by role.
    """
    # Create test users
    create_user(email="dentist@example.com",
                password="password123", roles=["dentist"])
    create_user(email="patient@example.com",
                password="password123", roles=["patient"])

    # admin login
    create_user(email="admin@example.com",
                password="admin123", roles=["admin"])
    response = api_client.post(
        "/api/login/", {"email": "admin@example.com", "password": "admin123"}
    )
    assert response.status_code == 200
    admin_token = response.cookies.get("access_token")
    print("admin Token (Cookie):", admin_token)
    assert admin_token is not None  # Ensure the token is retrieved

    # admin access to list all users
    api_client.cookies["access_token"] = admin_token.value
    response = api_client.get("/api/users/")
    print("Response Data:", response.data)
    assert response.status_code == 200
    assert len(response.data) >= 2  # Ensure users are listed

    # Filter users by role (e.g., dentist)
    response = api_client.get("/api/users/?role=dentist")
    assert response.status_code == 200
    assert len(response.data) == 1  # Only one user with the dentist role
    assert response.data[0]["email"] == "dentist@example.com"


@pytest.mark.django_db
def test_admin_update_user(api_client, create_user):
    """
    Test that an admin can update a specific user's details, including the role.
    """
    # Step 1: Create a receptionist user
    user = create_user(
        email="receptionist@example.com", password="password123", roles=["receptionist"]
    )

    # Step 2: Create an admin user and log in
    create_user(email="admin@example.com",
                password="admin_pass", roles=["admin"])
    response = api_client.post(
        "/api/login/", {"email": "admin@example.com", "password": "admin_pass"}
    )
    assert response.status_code == 200  # Ensure login is successful

    admin_token = response.cookies.get("access_token")
    assert admin_token is not None  # Ensure the token exists

    # Step 3: admin updates the user's details
    api_client.cookies["access_token"] = admin_token.value
    # print("Headers:", api_client._credentials)

    response = api_client.put(
        f"/api/users/{user.id}/",
        {
            "first_name": "Updated",
            "last_name": "User",
            "roles": ["patient"],  # Correct JSON array
        },
        format="json",
    )
    print("Response data:", response.data)
    assert response.status_code == 200  # Ensure the update is successful
    assert response.data["first_name"] == "Updated"
    assert response.data["last_name"] == "User"
    assert "patient" in response.data["roles"]


@pytest.mark.django_db
def test_admin_delete_user(api_client, create_user):
    """
    Test that an admin can delete a specific user.
    """
    # Step 1: Create the user to be deleted
    user = create_user(
        email="deletethis@example.com", password="password123", roles=["dentist"]
    )

    # Step 2: Create an admin user and log in
    create_user(email="admin@example.com",
                password="admin_pass", roles=["admin"])
    response = api_client.post(
        "/api/login/", {"email": "admin@example.com", "password": "admin_pass"}
    )
    assert response.status_code == 200  # Ensure login is successful
    admin_token = response.cookies.get("access_token")
    assert admin_token is not None  # Ensure the token exists

    # Step 3: admin deletes the user
    api_client.cookies["access_token"] = admin_token.value
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
        roles=["patient"],
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
    api_client.cookies["access_token"] = non_admin_token.value

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
            "roles": ["patient"],  # Attempt to change role
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
def test_filter_users_by_role(api_client, create_user):
    """
    Test filtering users by role using query parameters.
    """
    # Set up users with different roles
    create_user(email="dentist1@example.com",
                password="password123", roles=["dentist"])
    create_user(
        email="receptionist1@example.com",
        password="password123",
        roles=["receptionist"],
    )
    create_user(email="patient1@example.com",
                password="password123", roles=["patient"])

    # Step 1: Create and login as admin
    create_user(email="admin@example.com",
                password="admin_pass", roles=["admin"])
    response = api_client.post(
        "/api/login/", {"email": "admin@example.com", "password": "admin_pass"}
    )
    assert response.status_code == 200
    admin_token = response.cookies.get("access_token")
    assert admin_token is not None  # Ensure the token is present

    # Authenticate as admin
    api_client.cookies["access_token"] = admin_token.value

    # Step 2: Test with no query parameter (list all non-admin users)
    response = api_client.get("/api/users/")
    assert response.status_code == status.HTTP_200_OK

    # Exclude admin users manually in the test
    non_admin_users = [
        user for user in response.data if "admin" not in user["roles"]]
    assert len(non_admin_users) == 3

    # Step 3: Test filtering by role
    response = api_client.get("/api/users/?role=dentist")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) == 1
    assert response.data[0]["email"] == "dentist1@example.com"

    response = api_client.get("/api/users/?role=receptionist")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) == 1
    assert response.data[0]["email"] == "receptionist1@example.com"

    response = api_client.get("/api/users/?role=patient")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) == 1
    assert response.data[0]["email"] == "patient1@example.com"


@pytest.mark.django_db
def test_bulk_register_users(api_client, create_user):
    """
    ✅ Test bulk registration with valid and invalid inputs.
    """
    admin_user = create_user(email="admin@example.com",
                             password="admin_pass", roles=["admin"])
    api_client.force_authenticate(user=admin_user)

    valid_payload = {
        "users": [
            {
                "email": "user1@example.com",
                "password": "Password123!",
                "roles": ["patient"],  # ✅ Ensure roles exist
                "dob": "1990-01-01",
                "contact_info": "+1234567890",
                "first_name": "User1",
                "last_name": "Example",
                "gender": "Male",
                "blood_group": "O+",
            },
            {
                "email": "user2@example.com",
                "password": "SecurePass456!",
                "roles": ["receptionist", "dentist"],  # ✅ Ensure roles exist
                "dob": "1985-05-15",
                "contact_info": "+9876543210",
                "first_name": "User2",
                "last_name": "Example",
                "gender": "Female",
                "blood_group": "A-",
            },
        ]
    }

    # ✅ Perform bulk registration
    response = api_client.post(
        "/api/register/bulk/", valid_payload, format="json")

    # ✅ Assertions
    assert response.status_code == status.HTTP_201_CREATED
    assert response.data["success_count"] == 2
    assert response.data["failed_count"] == 0

    # ✅ Ensure correct response structure
    for user_data in response.data["details"]:
        assert "email" in user_data
        assert user_data["status"] == "success"
        assert user_data["message"] == "User registered successfully."


@pytest.mark.django_db
def test_bulk_register_users_non_admin(api_client, create_user):
    """
    ❌ Non-admin users should not be able to perform bulk registration.
    """

    # ✅ Create a non-admin user (e.g., a receptionist)
    non_admin_user = create_user(email="receptionist@example.com",
                                 password="securepass", roles=["receptionist"])

    # ✅ Authenticate as a non-admin
    api_client.force_authenticate(user=non_admin_user)

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
            },
            {
                "email": "user2@example.com",
                "password": "SecurePass456!",
                "roles": ["dentist"],
                "dob": "1985-05-15",
                "contact_info": "+9876543210",
                "first_name": "User2",
                "last_name": "Example",
                "gender": "Female",
                "blood_group": "A-",
            },
        ]
    }

    # ✅ Attempt bulk registration
    response = api_client.post(
        "/api/register/bulk/", valid_payload, format="json")

    # ✅ Validate response (should be forbidden)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "You do not have permission" in response.data["detail"]


@pytest.mark.django_db
def test_user_role_assignment(api_client, create_user):
    """
    ✅ Ensures correct roles are assigned and retrieved in BulkRegisterView.
    """

    # ✅ Create an admin user
    admin_user = create_user(email="admin@example.com",
                             password="adminpass", roles=["admin"])

    # ✅ Authenticate as admin
    api_client.force_authenticate(user=admin_user)

    valid_payload = {
        "users": [
            {
                "email": "roleuser1@example.com",
                "password": "Password123!",
                "roles": ["patient"],
                "dob": "1995-05-10",
                "contact_info": "+1234567890",
                "first_name": "RoleUser1",
                "last_name": "Example",
                "gender": "Male",
                "blood_group": "O+",
            },
            {
                "email": "roleuser2@example.com",
                "password": "SecurePass456!",
                "roles": ["dentist", "receptionist"],
                "dob": "1987-08-22",
                "contact_info": "+9876543210",
                "first_name": "RoleUser2",
                "last_name": "Example",
                "gender": "Female",
                "blood_group": "A-",
            },
        ]
    }

    # ✅ Perform bulk registration
    response = api_client.post(
        "/api/register/bulk/", valid_payload, format="json")

    # ✅ Assertions
    assert response.status_code == status.HTTP_201_CREATED
    assert response.data["success_count"] == 2
    assert response.data["failed_count"] == 0

    # ✅ Retrieve users and check assigned roles
    user1 = User.objects.get(email="roleuser1@example.com")
    user2 = User.objects.get(email="roleuser2@example.com")

    assert set(user1.roles.values_list("name", flat=True)) == {"patient"}
    assert set(user2.roles.values_list("name", flat=True)) == {
        "dentist", "receptionist"}

    # ✅ Validate response structure
    for user_data in response.data["details"]:
        assert "email" in user_data
        assert user_data["status"] == "success"
        assert user_data["message"] == "User registered successfully."


@pytest.mark.django_db
def test_bulk_register_users_no_roles(api_client, create_user):
    """
    ❌ Ensure users cannot be registered without at least one role.
    """

    # ✅ Create an admin user
    admin_user = create_user(email="admin@example.com",
                             password="adminpass", roles=["admin"])

    # ✅ Authenticate as admin
    api_client.force_authenticate(user=admin_user)

    invalid_payload = {
        "users": [
            {
                "email": "noroleuser@example.com",
                "password": "WeakPass123!",
                "roles": [],  # ❌ No roles provided
                "dob": "1995-07-15",
                "contact_info": "+1234567890",
                "first_name": "NoRoleUser",
                "last_name": "Example",
                "gender": "Male",
                "blood_group": "O+",
            }
        ]
    }

    # ✅ Attempt bulk registration with missing roles
    response = api_client.post(
        "/api/register/bulk/", invalid_payload, format="json")

    # ✅ Ensure registration fails due to missing roles
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    # ✅ Extract "roles" error from nested "details"
    assert "roles" in response.data["details"]
    assert response.data["details"]["roles"][0] == "A user must have at least one role assigned."


@pytest.mark.django_db
def test_bulk_register_users_invalid_data(api_client, create_user):
    """
    ❌ Ensures bulk registration fails when invalid data is provided.
    """

    admin_user = create_user(email="admin@example.com",
                             password="adminpass", roles=["admin"])
    api_client.force_authenticate(user=admin_user)

    invalid_payload = {
        "users": [
            {
                "email": "invalid-email",  # ❌ Invalid email format
                "password": "Password123!",
                "roles": ["patient"],
                "dob": "1990-01-01",
                "contact_info": "+1234567890",
                "first_name": "User1",
                "last_name": "Example",
                "gender": "Male",
                "blood_group": "O+",
            },
            {
                "email": "user2@example.com",
                "password": "",  # ❌ Empty password
                "roles": ["dentist", "receptionist"],
                "dob": "1985-05-15",
                "contact_info": "+9876543210",
                "first_name": "User2",
                "last_name": "Example",
                "gender": "Female",
                "blood_group": "A-",
            },
            {
                "email": "user3@example.com",
                "password": "ValidPass123!",
                "roles": [],  # ❌ No roles provided
                "dob": "1985-05-15",
                "contact_info": "+9876543210",
                "first_name": "User3",
                "last_name": "Example",
                "gender": "Female",
                "blood_group": "A-",
            },
        ]
    }

    response = api_client.post(
        "/api/register/bulk/", invalid_payload, format="json")

    # ✅ Ensure response returns 400 Bad Request
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    response_data = response.data
    print("📌 Response Data:", response_data)

    # ✅ Ensure validation errors exist in the response
    assert "details" in response_data  # ✅ Ensure 'details' exists
    # ✅ Ensure 'roles' validation error is present
    assert "roles" in response_data["details"]

    # ✅ Ensure the correct error messages
    assert "A user must have at least one role assigned." in response_data["details"]["roles"]
