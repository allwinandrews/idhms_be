import pytest
from rest_framework import status
from api.models import Appointment
from django.utils.timezone import make_aware, is_aware, now, timedelta

from datetime import datetime


@pytest.mark.django_db
def test_receptionist_create_appointment(api_client, receptionist_token, create_user):
    """
    Test that a Receptionist can create an appointment.
    """
    # Create a test patient and dentist
    patient = create_user(
        email="patient@example.com", password="password123", role="Patient"
    )
    dentist = create_user(
        email="dentist@example.com", password="password123", role="Dentist"
    )

    # Define a dynamic future appointment date
    appointment_date = now() + timedelta(days=1)  # Always 1 day ahead
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {receptionist_token}")
    response = api_client.post(
        "/api/appointments/",
        {
            "patient": patient.id,
            "dentist": dentist.id,
            "appointment_date": appointment_date.isoformat(),
            "status": "Scheduled",
        },
    )
    print(response.data)  # Debugging output
    assert response.status_code == status.HTTP_201_CREATED


@pytest.mark.django_db
def test_receptionist_list_appointments(
    api_client, receptionist_token, create_appointments
):
    """
    Test that a Receptionist can list all appointments.
    """
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {receptionist_token}")
    response = api_client.get("/api/appointments/")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) == Appointment.objects.count()


@pytest.mark.django_db
def test_dentist_list_appointments(api_client, dentist_token, create_appointments):
    """
    Test that a Dentist can list their assigned appointments.
    """
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {dentist_token}")
    response = api_client.get("/api/appointments/")
    assert response.status_code == status.HTTP_200_OK
    # Ensure only assigned appointments are listed
    for appointment in response.data:
        assert appointment["dentist"] == api_client.handler._force_user.id


@pytest.mark.django_db
def test_patient_list_appointments(api_client, patient_token, create_appointments):
    """
    Test that a Patient can list their own appointments.
    """
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {patient_token}")
    response = api_client.get("/api/appointments/")
    assert response.status_code == status.HTTP_200_OK
    # Ensure only the patient's appointments are listed
    for appointment in response.data:
        assert appointment["patient"] == api_client.handler._force_user.id


@pytest.mark.django_db
def test_update_appointment_by_receptionist(
    api_client, receptionist_token, create_appointments
):
    """
    Test that a Receptionist can update an appointment.
    """
    appointment = Appointment.objects.first()
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {receptionist_token}")
    response = api_client.patch(
        f"/api/appointments/{appointment.id}/", {"status": "Completed"}
    )
    print(appointment.patient.id == appointment.dentist.id)
    print(f"Patient ID: {appointment.patient.id}, Dentist ID: {appointment.dentist.id}")
    print(response.data)  # Debug the validation error
    assert response.status_code == status.HTTP_200_OK
    assert Appointment.objects.get(id=appointment.id).status == "Completed"


@pytest.mark.django_db
def test_delete_appointment_by_receptionist(
    api_client, receptionist_token, create_appointments
):
    """
    Test that a Receptionist can delete an appointment.
    """
    appointment = Appointment.objects.first()
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {receptionist_token}")
    response = api_client.delete(f"/api/appointments/{appointment.id}/")
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not Appointment.objects.filter(id=appointment.id).exists()
