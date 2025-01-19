from rest_framework import serializers
from api.models import Appointment, Role
import re
from datetime import date
from django.db import transaction

from django.utils.timezone import is_aware, make_aware, now
from django.utils.crypto import get_random_string  # For generating unique baby IDs

from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()

import logging

logger = logging.getLogger(__name__)


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for basic user information.
    """

    email = serializers.EmailField(required=True)
    contact_info = serializers.RegexField(
        regex=r"^\+?[1-9]\d{1,14}$",
        required=False,
        error_messages={
            "invalid": "Enter a valid phone number in international format (e.g., +123456789)."
        },
    )

    gender = serializers.ChoiceField(
        choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")],
        required=False,
    )
    roles = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field="name",  # Serialize roles as their names
    )

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "contact_info",
            "roles",  # Updated to reflect Many-to-Many roles
            "gender",
        ]
        extra_kwargs = {
            "email": {"required": True},
        }


class GuardianSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=100, required=True)
    last_name = serializers.CharField(max_length=100, required=True)
    email = serializers.EmailField(required=False)
    password = serializers.CharField(write_only=True, required=False)
    contact_info = serializers.RegexField(
        regex=r"^\+?[1-9]\d{1,14}$",
        required=False,
        error_messages={
            "invalid": "Enter a valid phone number in international format (e.g., +123456789)."
        },
    )

    roles = serializers.SlugRelatedField(
        many=True, queryset=Role.objects.all(), slug_field="name", required=True
    )
    dob = serializers.DateField(required=True)
    gender = serializers.ChoiceField(
        choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")],
        required=True,
    )
    blood_group = serializers.ChoiceField(
        choices=[
            ("A+", "A+"),
            ("A-", "A-"),
            ("B+", "B+"),
            ("B-", "B-"),
            ("O+", "O+"),
            ("O-", "O-"),
            ("AB+", "AB+"),
            ("AB-", "AB-"),
        ],
        required=True,
    )


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration with email, contact info handling, and roles.
    Supports inline guardian registration for baby accounts.
    """

    contact_info = serializers.RegexField(
        regex=r"^\+?[1-9]\d{1,14}$",
        required=False,
        error_messages={
            "invalid": "Enter a valid phone number in international format (e.g., +123456789)."
        },
    )
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(max_length=100, required=True)
    last_name = serializers.CharField(max_length=100, required=True)
    dob = serializers.DateField(required=True)
    gender = serializers.ChoiceField(
        choices=[("Male", "Male"), ("Female", "Female"), ("Other", "Other")],
        required=True,
    )
    blood_group = serializers.ChoiceField(
        choices=[
            ("A+", "A+"),
            ("A-", "A-"),
            ("B+", "B+"),
            ("B-", "B-"),
            ("O+", "O+"),
            ("O-", "O-"),
            ("AB+", "AB+"),
            ("AB-", "AB-"),
        ],
        required=True,
    )
    guardian = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(roles__name="Patient"), required=False
    )
    guardian_data = GuardianSerializer(required=False)
    roles = serializers.SlugRelatedField(
        many=True, queryset=Role.objects.all(), slug_field="name", required=True
    )

    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "email",
            "password",
            "roles",
            "contact_info",
            "dob",
            "gender",
            "blood_group",
            "guardian",
            "guardian_data",
        ]
        extra_kwargs = {"password": {"write_only": True, "required": False}}

    def validate(self, data):
        """
        Custom validation for user registration logic.
        """
        # At least one contact method or guardian must be provided
        if (
            not data.get("email")
            and not data.get("contact_info")
            and not data.get("guardian")
            and not data.get("guardian_data")
        ):
            raise serializers.ValidationError(
                "Provide email, contact info, or a guardian."
            )

        # Ensure no conflicts between guardian and guardian_data
        if data.get("guardian_data") and data.get("guardian"):
            raise serializers.ValidationError(
                "Provide either 'guardian' or 'guardian_data', not both."
            )

        # Validate roles
        role_names = [
            role.name if isinstance(role, Role) else role
            for role in data.get("roles", [])
        ]
        valid_roles = list(Role.objects.values_list("name", flat=True))
        invalid_roles = [role for role in role_names if role not in valid_roles]
        if invalid_roles:
            raise serializers.ValidationError(
                {"roles": f"Invalid roles: {', '.join(invalid_roles)}"}
            )

        # Ensure guardian is 18+ if provided
        guardian = data.get("guardian")
        if guardian and guardian.dob >= date.today().replace(
            year=date.today().year - 18
        ):
            raise serializers.ValidationError(
                {"guardian": "Guardian must be at least 18 years old."}
            )

        return data

    def validate_dob(self, value):
        """
        Ensure the date of birth is in the past.
        """
        if value >= now().date():
            raise serializers.ValidationError("Date of birth must be in the past.")
        return value

    def validate_email(self, value):
        """
        Ensure the email is unique.
        """
        if value and User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def create(self, validated_data):
        """
        Create a new user instance with the validated data.
        """
        validated_data.pop("username", None)
        # Generate email and password if missing
        if not validated_data.get("email"):
            validated_data["email"] = f"USER-{get_random_string(6)}@hospital.local"
        if not validated_data.get("password"):
            validated_data["password"] = get_random_string(12)

        # Extract roles and guardian details
        roles = validated_data.pop("roles", [])
        guardian_data = validated_data.pop("guardian_data", None)
        guardian = validated_data.pop("guardian", None)

        # Handle inline guardian creation
        if guardian_data:
            guardian_roles = guardian_data.pop("roles", [])
            guardian_roles_instances = Role.objects.filter(name__in=guardian_roles)
            guardian_email = guardian_data.get("email")
            if not guardian_email:
                guardian_email = f"GUARDIAN-{get_random_string(6)}@hospital.local"
            guardian = User.objects.create_user(
                email=guardian_email,
                password=guardian_data.get("password", get_random_string(12)),
                first_name=guardian_data.get("first_name", "Guardian"),
                last_name=guardian_data.get("last_name", "User"),
                dob=guardian_data.get(
                    "dob", date.today().replace(year=date.today().year - 30)
                ),
                contact_info=guardian_data.get("contact_info"),
            )
            guardian.roles.set(guardian_roles_instances)
            validated_data["guardian"] = guardian

        # Create the main user
        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            dob=validated_data["dob"],
            gender=validated_data["gender"],
            blood_group=validated_data["blood_group"],
            contact_info=validated_data.get("contact_info"),
            guardian=validated_data.get("guardian"),
        )

        # Assign roles
        user.roles.set(Role.objects.filter(name__in=roles))
        return user


class BulkRegisterSerializer(serializers.Serializer):
    users = serializers.ListField(
        child=serializers.DictField(),  # Accept dictionaries for each user
        allow_empty=False,
        help_text="A list of user registration data.",
    )

    def validate(self, data):
        """
        Validate bulk user data.
        """
        # Validate unique emails within the bulk request
        emails = [
            user_data["email"] for user_data in data["users"] if "email" in user_data
        ]
        duplicate_emails = {email for email in emails if emails.count(email) > 1}

        if duplicate_emails:
            raise serializers.ValidationError(
                {
                    "users": f"Duplicate emails found in the request: {', '.join(duplicate_emails)}"
                }
            )

        # Validate roles explicitly
        valid_roles = set(Role.objects.values_list("name", flat=True))
        logger.debug(f"Valid roles from DB: {valid_roles}")

        for idx, user_data in enumerate(data["users"]):
            roles = user_data.get("roles", [])
            logger.debug(f"Validating roles for user {idx}: {roles}")

            invalid_roles = [role for role in roles if role not in valid_roles]
            if invalid_roles:
                logger.error(f"Invalid roles found for user {idx}: {invalid_roles}")
                raise serializers.ValidationError(
                    {"roles": f"Invalid roles provided: {', '.join(invalid_roles)}"}
                )

        return data

    def create(self, validated_data):
        """
        Bulk user creation logic with inline guardian handling and transaction safety.
        """
        users_data = validated_data["users"]
        created_users = []
        response_details = []  # Collect details for success and failure

        with transaction.atomic():
            for idx, user_data in enumerate(users_data):
                try:
                    logger.debug(f"Processing user {idx}: {user_data}")

                    # Convert roles to Role objects
                    roles = user_data.pop("roles", [])
                    logger.debug(f"Converting roles to Role objects: {roles}")
                    role_objects = Role.objects.filter(name__in=roles)
                    user_data["roles"] = role_objects

                    # Create the user using RegisterSerializer
                    serializer = RegisterSerializer(data=user_data)
                    serializer.is_valid(raise_exception=True)
                    user = serializer.save()
                    created_users.append(user)

                    # Add success detail
                    response_details.append(
                        {
                            "email": user.email,
                            "status": "success",
                            "message": "User registered successfully.",
                        }
                    )

                except serializers.ValidationError as e:
                    # Handle validation errors
                    logger.error(f"Validation error for user {idx}: {e.detail}")
                    response_details.append(
                        {
                            "email": user_data.get("email", "Unknown"),
                            "status": "failed",
                            "errors": e.detail,  # Provide detailed validation errors
                        }
                    )

                except Exception as e:
                    # Handle unexpected errors
                    logger.error(f"Unexpected error for user {idx}: {str(e)}")
                    response_details.append(
                        {
                            "email": user_data.get("email", "Unknown"),
                            "status": "failed",
                            "errors": {"non_field_errors": [str(e)]},
                        }
                    )

        return {
            "success_count": len(created_users),
            "failed_count": len(users_data) - len(created_users),
            "details": response_details,
        }


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
