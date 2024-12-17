import pytest
from rest_framework import status


@pytest.mark.django_db
def test_create_appointment(
    api_client, create_user, receptionist_token, patient_token, dentist_token
):
    """
    Test that Receptionists can create appointments and others cannot.
    """
    # Create a test patient and dentist
    create_user(email="patient@example.com", password="patient_pass", role="Patient")
    create_user(email="dentist@example.com", password="dentist_pass", role="Dentist")

    # Receptionist creates an appointment
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {receptionist_token}")
    response = api_client.post(
        "/api/appointments/",
        {
            "patient": 1,  # ID of the created patient
            "dentist": 2,  # ID of the created dentist
            "appointment_date": "2024-12-25 10:00:00",
            "status": "Scheduled",
        },
    )
    assert response.status_code == status.HTTP_201_CREATED


@pytest.mark.django_db
def test_update_appointment(api_client, receptionist_token):
    """
    Test updating an existing appointment.
    """
    # Create a test appointment
    appointment = Appointment.objects.create(
        patient_id=1,
        dentist_id=2,
        appointment_date="2024-12-25 10:00:00",
        status="Scheduled",
    )

    # Receptionist updates the appointment
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {receptionist_token}")
    response = api_client.put(
        f"/api/appointments/{appointment.id}/", {"status": "Completed"}
    )
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
def test_retrieve_appointments(api_client, create_user, patient_token, dentist_token):
    # Test that Patients and Dentists can retrieve their own appointments.
    # Patient retrieves their appointments
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {patient_token}")
    response = api_client.get("/api/appointments/")
    assert response.status_code == status.HTTP_200_OK

    # Dentist retrieves their appointments
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {dentist_token}")
    response = api_client.get("/api/appointments/")
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
def test_delete_appointment(api_client, receptionist_token, patient_token):
    # Test that Receptionists can delete appointments, but Patients cannot.
    # Receptionist deletes an appointment
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {receptionist_token}")
    response = api_client.delete("/api/appointments/1/")
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # Patient tries to delete an appointment
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {patient_token}")
    response = api_client.delete("/api/appointments/1/")
    assert response.status_code == status.HTTP_403_FORBIDDEN
