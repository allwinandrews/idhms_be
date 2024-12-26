from rest_framework import serializers
from api.models import Appointment
import re

# from datetime import date,datetime
from django.utils.timezone import is_aware, make_aware

from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    # Serializer for basic user information.
    email = serializers.EmailField(required=True)
    contact_info = serializers.CharField(required=False)
    gender = serializers.ChoiceField(
        choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")],
        required=False,
    )

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "contact_info",
            "role",
            "gender",
        ]
        extra_kwargs = {
            "email": {"required": True},
            "role": {"required": False},  # Allow updates to role
        }


class RegisterSerializer(serializers.ModelSerializer):
    # Serializer for user registration, with email as the unique identifier

    contact_info = serializers.CharField(max_length=15, required=True)
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(max_length=100, required=True)
    last_name = serializers.CharField(max_length=100, required=True)
    dob = serializers.DateField(required=True)
    GENDER_CHOICES = [
        ("Male", "Male"),
        ("Female", "Female"),
        ("Other", "Other"),
    ]

    gender = serializers.ChoiceField(choices=GENDER_CHOICES)

    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "email",
            "password",
            "role",
            "contact_info",
            "dob",
            "gender",
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
            contact_info=validated_data["contact_info"],
            dob=validated_data["dob"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            gender=validated_data["gender"],
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
        """
        Ensure the appointment date is not in the past.
        """
        # Ensure timezone-awareness
        print(f"appointment_date: {value}, now: {timezone.now()}")
        if not is_aware(value):
            value = make_aware(value)

        if value < timezone.now():
            raise serializers.ValidationError("Appointment date cannot be in the past.")
        return value

    def validate(self, data):
        # Use instance values if fields are missing in partial updates
        patient = data.get("patient", getattr(self.instance, "patient", None))
        dentist = data.get("dentist", getattr(self.instance, "dentist", None))

        # Check if patient and dentist are the same
        if patient == dentist:
            raise serializers.ValidationError(
                "Patient and Dentist cannot be the same person."
            )
        return data
