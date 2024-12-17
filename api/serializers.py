from rest_framework import serializers
from api.models import User, Appointment
import re
from datetime import date


class UserSerializer(serializers.ModelSerializer):
    # Serializer for basic user information.
    # Used for non-sensitive data retrieval (e.g., username, email, and role).
    class Meta:
        model = User
        fields = ["id", "username", "email", "role"]


class RegisterSerializer(serializers.ModelSerializer):
    # Serializer for user registration, with email as the unique identifier

    phone_number = serializers.CharField(max_length=15, required=True)
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(max_length=100, required=True)
    last_name = serializers.CharField(max_length=100, required=True)
    dob = serializers.DateField(required=True)

    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "email",
            "password",
            "role",
            "phone_number",
            "dob",
        ]
        extra_kwargs = {"password": {"write_only": True}}

    def validate_phone_number(self, value):
        # Validate phone number format.
        import re

        if not re.match(r"^\+?\d{10,15}$", value):
            raise serializers.ValidationError("Phone number must be 10-15 digits.")
        return value

    def validate_dob(self, value):
        # Validate that the date of birth is in the past.
        from datetime import date

        if value >= date.today():
            raise serializers.ValidationError("Date of birth must be in the past.")
        return value

    def validate_email(self, value):
        # Ensure the email is unique.
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def create(self, validated_data):

        # Create a new user instance with the validated data.
        # Use email as the unique identifier and store the name.

        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            role=validated_data.get("role", "Patient"),
            contact_info=validated_data["phone_number"],
            dob=validated_data["dob"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
        )
        return user


class AppointmentSerializer(serializers.ModelSerializer):
    # Serializer for the Appointment model.
    # Handles serialization and validation for appointments.
    class Meta:
        model = Appointment
        fields = ["id", "patient", "dentist", "appointment_date", "status"]
        read_only_fields = ["id"]  # ID is automatically generated

    def validate_appointment_date(self, value):

        # Validate that the appointment date is in the future.

        from datetime import datetime

        if value < datetime.now():
            raise serializers.ValidationError("Appointment date must be in the future.")
        return value

    def validate(self, data):
        # Custom validation to ensure patient and dentist are not the same.
        if data.get("patient") == data.get("dentist"):
            raise serializers.ValidationError(
                "Patient and Dentist cannot be the same person."
            )
        return data
