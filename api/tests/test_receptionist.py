import pytest
from rest_framework import status


@pytest.mark.django_db
def test_receptionist_create_patient(api_client, receptionist_token):
    """
    Test that a receptionist can create a patient.
    """
    # receptionist creates a patient
    api_client.cookies["access_token"] = receptionist_token.value
    response = api_client.post(
        "/api/receptionist/manage-patients/",
        {
            "first_name": "John",
            "last_name": "Doe",
            "email": "johndoe@email.com",
            "contact_info": "+1234567890",
            "dob": "1990-01-01",
            "gender": "Male",
            "blood_group": "A+",
        },
    )
    print(response.data)
    assert response.status_code == status.HTTP_201_CREATED
    assert response.data["message"] == "patient John Doe created successfully!"


@pytest.mark.django_db
def test_receptionist_list_patients(api_client, receptionist_token, create_patients):
    """
    Test that a receptionist can list all patients.
    """
    # Authenticate as receptionist
    api_client.cookies["access_token"] = receptionist_token.value

    # Fetch the patient list
    response = api_client.get("/api/receptionist/manage-patients/")
    assert response.status_code == status.HTTP_200_OK

    # Validate the number of patients retrieved
    assert len(response.data) == len(create_patients)

    # Ensure the data matches the created patients
    retrieved_emails = [patient["email"] for patient in response.data]
    created_emails = [patient.email for patient in create_patients]
    assert set(retrieved_emails) == set(created_emails)


@pytest.mark.django_db
def test_unauthorized_access_to_manage_patients(
    api_client, create_user, patient_token, dentist_token, admin_token
):
    """
    Test that non-receptionist roles cannot access the manage patients endpoint.
    """
    # patient tries to access the endpoint
    api_client.cookies["access_token"] = patient_token.value
    response = api_client.get("/api/receptionist/manage-patients/")
    assert response.status_code == status.HTTP_403_FORBIDDEN

    # dentist tries to access the endpoint
    api_client.cookies["access_token"] = dentist_token.value
    response = api_client.get("/api/receptionist/manage-patients/")
    assert response.status_code == status.HTTP_403_FORBIDDEN

    # admin tries to access the endpoint
    api_client.cookies["access_token"] = admin_token.value
    response = api_client.get("/api/receptionist/manage-patients/")
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_create_patient_with_invalid_data(api_client, receptionist_token):
    """
    Test that creating a patient with invalid data fails.
    """
    # receptionist attempts to create a patient with missing fields
    api_client.cookies["access_token"] = receptionist_token.value
    response = api_client.post(
        "/api/receptionist/manage-patients/",
        {"contact_info": "+1234567890", "dob": "1990-01-01"},
    )
    print(response.data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "first_name" in response.data
    assert "last_name" in response.data
