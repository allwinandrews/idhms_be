import pytest
from rest_framework import status
from api.models import User, Role


@pytest.mark.django_db
def test_admin_can_assign_roles(api_client, create_user):
    """
    ✅ Admin users should be able to assign valid roles to another user.
    """
    print("📌 Existing Roles in DB:", list(
        Role.objects.values_list("name", flat=True)))
    admin_user = create_user(email="admin@example.com",
                             password="adminpass", roles=["admin"])
    target_user = create_user(email="user@example.com",
                              password="userpass", roles=["patient"])

    # ✅ Create required roles explicitly before the test
    Role.objects.get_or_create(name="dentist")
    Role.objects.get_or_create(name="receptionist")

    api_client.force_authenticate(user=admin_user)

    # ✅ Send request with correctly formatted role names
    response = api_client.post(
        f"/api/users/{target_user.id}/roles/", {
            "roles": ["dentist", "receptionist"]}  # ✅ Ensure correct role names
    )

    print("📌 Existing Roles in DB:", list(
        Role.objects.values_list("name", flat=True)))

    print("📌 Role Assignment Response:", response.data)  # Debugging Output

    assert response.status_code == status.HTTP_200_OK
    assert sorted(response.data["roles"]) == sorted(
        ["dentist", "receptionist"])


@pytest.mark.django_db
def test_non_admin_cannot_assign_roles(api_client, create_user):
    """
    ❌ Non-admin users should not be able to assign roles.
    """
    patient_user = create_user(
        email="patient@example.com", password="patientpass", roles=["patient"])
    target_user = create_user(email="user@example.com",
                              password="userpass", roles=["patient"])

    api_client.force_authenticate(user=patient_user)
    response = api_client.post(
        f"/api/users/{target_user.id}/roles/", {"roles": ["dentist"]})

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "You do not have permission" in response.data["detail"]


@pytest.mark.django_db
def test_only_superuser_can_assign_admin_role(api_client, create_user):
    """
    ✅ Superusers should be able to assign 'admin' role, but regular admins should not.
    """
    superuser = create_user(email="superuser@example.com",
                            password="superpass", roles=["admin"], is_superuser=True)
    regular_admin = create_user(
        email="admin@example.com", password="adminpass", roles=["admin"])
    target_user = create_user(email="user@example.com",
                              password="userpass", roles=["patient"])

    # ✅ Superuser can assign 'admin' role
    api_client.force_authenticate(user=superuser)
    response = api_client.post(
        f"/api/users/{target_user.id}/roles/", {"roles": ["admin"]})
    assert response.status_code == status.HTTP_200_OK
    assert "admin" in response.data["roles"]

    # ❌ Regular admin should NOT be able to assign 'admin' role
    api_client.force_authenticate(user=regular_admin)
    response = api_client.post(
        f"/api/users/{target_user.id}/roles/", {"roles": ["admin"]})
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_invalid_roles_are_rejected(api_client, create_user):
    """
    ❌ Invalid roles should be rejected.
    """
    admin_user = create_user(email="admin@example.com",
                             password="adminpass", roles=["admin"])
    target_user = create_user(email="user@example.com",
                              password="userpass", roles=["patient"])

    api_client.force_authenticate(user=admin_user)
    response = api_client.post(
        f"/api/users/{target_user.id}/roles/", {"roles": ["invalidrole"]})

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid roles provided: invalidrole" in response.data["detail"]


@pytest.mark.django_db
def test_user_must_have_at_least_one_role(api_client, create_user):
    """
    ❌ A user cannot have zero roles.
    """
    admin_user = create_user(email="admin@example.com",
                             password="adminpass", roles=["admin"])
    target_user = create_user(email="user@example.com",
                              password="userpass", roles=["patient"])

    api_client.force_authenticate(user=admin_user)
    response = api_client.post(
        f"/api/users/{target_user.id}/roles/", {"roles": []})

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "A valid list of roles is required." in response.data["detail"]
