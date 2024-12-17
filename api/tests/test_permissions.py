import pytest


@pytest.mark.django_db
def test_admin_only_view(api_client, create_user):
    """
    Test access to admin-only endpoint.
    """
    # Create an admin user and a regular patient user
    create_user(email="admin_user@example.com", password="admin_pass", role="Admin")
    create_user(
        email="patient_user@example.com", password="patient_pass", role="Patient"
    )

    # Admin login
    response = api_client.post(
        "/api/login/", {"email": "admin_user@example.com", "password": "admin_pass"}
    )
    assert response.status_code == 200
    admin_token = response.data["access"]

    # Patient login (for comparison)
    response = api_client.post(
        "/api/login/", {"email": "patient_user@example.com", "password": "patient_pass"}
    )
    assert response.status_code == 200
    patient_token = response.data["access"]

    # Admin access to the endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_token}")
    response = api_client.get("/api/admin/")
    assert response.status_code == 200
    assert response.data["message"] == "Welcome, Admin!"

    # Patient access to the endpoint (should be forbidden)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {patient_token}")
    response = api_client.get("/api/admin/")
    assert response.status_code == 403


@pytest.mark.django_db
def test_patient_data_view(api_client, create_user):
    """
    Test access to patient data for Patient role.
    """
    # Create patient user
    create_user(
        email="patient_user@example.com", password="patient_pass", role="Patient"
    )

    # Patient login
    response = api_client.post(
        "/api/login/", {"email": "patient_user@example.com", "password": "patient_pass"}
    )
    assert response.status_code == 200
    patient_token = response.data["access"]

    # Access patient data endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {patient_token}")
    response = api_client.get("/api/patient/data/")
    assert response.status_code == 200


@pytest.mark.django_db
def test_patient_access(api_client, create_user):
    """
    Test patient access to their data endpoint.
    """
    # Create patient user
    create_user(
        email="patient_user@example.com", password="patient_pass", role="Patient"
    )

    # Patient login
    response = api_client.post(
        "/api/login/", {"email": "patient_user@example.com", "password": "patient_pass"}
    )
    assert response.status_code == 200
    patient_token = response.data["access"]

    # Access patient data endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {patient_token}")
    response = api_client.get("/api/patient/data/")
    assert response.status_code == 200


@pytest.mark.django_db
def test_dentist_appointments_access(api_client, create_user):
    # Test access to dentist appointments endpoint for Dentist role.
    # Create dentist user
    create_user(
        email="dentist_user@example.com", password="dentist_pass", role="Dentist"
    )

    # Dentist login
    response = api_client.post(
        "/api/login/", {"email": "dentist_user@example.com", "password": "dentist_pass"}
    )
    assert response.status_code == 200
    dentist_token = response.data["access"]

    # Access dentist appointments endpoint
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {dentist_token}")
    response = api_client.get("/api/dentist/appointments/")
    assert response.status_code == 200


@pytest.mark.django_db
def test_receptionist_manage_patients(api_client, receptionist_token):
    """
    Test that Receptionists can manage patient records.
    """
    # Receptionist access
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {receptionist_token}")
    response = api_client.post(
        "/api/receptionist/manage-patients/",
        {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe@example.com",
            "contact_info": "+1234567890",
            "dob": "1990-05-15",
            "gender": "Male",
        },
    )
    assert response.status_code == 201
    assert response.data["message"] == "Patient John Doe created successfully!"

    # Duplicate email test
    response = api_client.post(
        "/api/receptionist/manage-patients/",
        {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe@example.com",  # Reuse the same email
            "contact_info": "+9876543210",
            "dob": "1995-01-01",
            "gender": "Female",
        },
    )
    assert response.status_code == 400
    assert response.data["error"] == "Email already exists."
