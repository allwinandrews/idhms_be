import uuid
import pytest
from rest_framework import status


@pytest.mark.django_db
def test_admin_only_view(api_client, create_user):
    """
    Test access to admin-only endpoint.
    """
    # Create an admin user and a regular patient user
    admin_user = create_user(
        email="admin_user@example.com", password="admin_pass", roles=["Admin"]
    )
    patient_user = create_user(
        email="patient_user@example.com", password="patient_pass", roles=["Patient"]
    )

    # Admin login
    response = api_client.post(
        "/api/login/", {"email": "admin_user@example.com", "password": "admin_pass"}
    )
    assert response.status_code == 200
    admin_token = response.cookies.get("access_token")
    assert admin_token is not None  # Ensure the token exists

    # Patient login (for comparison)
    response = api_client.post(
        "/api/login/", {"email": "patient_user@example.com", "password": "patient_pass"}
    )
    assert response.status_code == 200
    patient_token = response.cookies.get("access_token")
    assert patient_token is not None  # Ensure the token exists

    # Admin access to the endpoint
    # print('admin_token.value',admin_token.value)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token.value}")
    response = api_client.get("/api/admin/")
    assert response.status_code == 200
    assert response.data["message"] == "Welcome, Admin!"

    # Patient access to the endpoint (should be forbidden)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {patient_token.value}")
    response = api_client.get("/api/admin/")
    assert response.status_code == 403
    assert (
        response.data["detail"] == "You do not have permission to perform this action."
    )


@pytest.mark.django_db
def test_patient_data_view(api_client, create_user):
    """
    Test access to patient data for Patient role.
    """
    # Create patient user
    create_user(
        email="patient_user@example.com", password="patient_pass", roles=["Patient"]
    )

    # Patient login
    response = api_client.post(
        "/api/login/", {"email": "patient_user@example.com", "password": "patient_pass"}
    )
    assert response.status_code == 200
    patient_token = response.cookies.get("access_token")

    # Access patient data endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {patient_token.value}")
    response = api_client.get("/api/patient/data/")
    assert response.status_code == 200


@pytest.mark.django_db
def test_patient_access(api_client, create_user):
    """
    Test patient access to their data endpoint.
    """
    # Create patient user
    create_user(
        email="patient_user@example.com", password="patient_pass", roles=["Patient"]
    )

    # Patient login
    response = api_client.post(
        "/api/login/", {"email": "patient_user@example.com", "password": "patient_pass"}
    )
    assert response.status_code == 200
    patient_token = response.cookies.get("access_token")

    # Access patient data endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {patient_token.value}")
    response = api_client.get("/api/patient/data/")
    assert response.status_code == 200


@pytest.mark.django_db
def test_dentist_appointments_access(api_client, create_user):
    # Test access to dentist appointments endpoint for Dentist role.
    # Create dentist user
    create_user(
        email="dentist_user@example.com", password="dentist_pass", roles=["Dentist"]
    )

    # Dentist login
    response = api_client.post(
        "/api/login/", {"email": "dentist_user@example.com", "password": "dentist_pass"}
    )
    assert response.status_code == 200
    dentist_token = response.cookies.get("access_token")

    # Access dentist appointments endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {dentist_token.value}")
    response = api_client.get("/api/appointments/")
    print(response.data)  # Debug output
    assert response.status_code == 200


@pytest.mark.django_db(transaction=True)
def test_receptionist_manage_patients(api_client, receptionist_token):
    """
    Test that Receptionists can manage patient records.
    """
    # Receptionist access
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {receptionist_token.value}")

    # Create a patient with unique email
    unique_email = f"john.doe+{uuid.uuid4().hex}@example.com"
    response = api_client.post(
        "/api/receptionist/manage-patients/",
        {
            "first_name": "John",
            "last_name": "Doe",
            "email": unique_email,  # Generate unique email
            "contact_info": "+1234567890",
            "dob": "1990-05-15",
            "gender": "Male",
            "blood_group": "O+",
        },
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.data["message"] == f"Patient John Doe created successfully!"

    # Duplicate email test
    response = api_client.post(
        "/api/receptionist/manage-patients/",
        {
            "first_name": "Jane",
            "last_name": "Doe",
            "email": unique_email,  # Reuse the same email
            "contact_info": "+9876543210",
            "dob": "1995-01-01",
            "gender": "Female",
            "blood_group": "A-",  # Add the required field
        },
    )
    print("response", response.data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    # Check for validation error
    assert "email" in response.data
    assert response.data["email"][0] == "Email already exists."
