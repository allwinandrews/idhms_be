import logging
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
        queryset=User.objects.filter(roles__name="patient"), required=False
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
        invalid_roles = [
            role for role in role_names if role not in valid_roles]
        if invalid_roles:
            raise serializers.ValidationError(
                {"roles": f"Invalid roles: {', '.join(invalid_roles)}"}
            )

        # Ensure guardian is 18+ if provided
        guardian = data.get("guardian")
        if guardian and guardian.dob and guardian.dob >= date.today().replace(
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
            raise serializers.ValidationError(
                "Date of birth must be in the past.")
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

        # ✅ Ensure guardian is properly assigned
        if guardian and not isinstance(guardian, User):
            guardian = User.objects.filter(id=guardian.id).first()

        # Handle inline guardian creation
        if guardian_data:
            guardian_roles = guardian_data.pop("roles", [])
            guardian_roles_instances = Role.objects.filter(
                name__in=guardian_roles)
            guardian_email = guardian_data.get(
                "email", f"GUARDIAN-{get_random_string(6)}@hospital.local")

            guardian, created = User.objects.get_or_create(
                email=guardian_email,
                defaults={
                    "password": guardian_data.get("password", get_random_string(12)),
                    "first_name": guardian_data.get("first_name", "Guardian"),
                    "last_name": guardian_data.get("last_name", "User"),
                    "dob": guardian_data.get("dob", date.today().replace(year=date.today().year - 30)),
                    "contact_info": guardian_data.get("contact_info"),
                },
            )
            if created:
                guardian.roles.set(guardian_roles_instances)

        # ✅ Ensure guardian is always set
        validated_data["guardian"] = guardian

        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            dob=validated_data["dob"],
            gender=validated_data["gender"],
            blood_group=validated_data["blood_group"],
            contact_info=validated_data.get("contact_info"),
            # ✅ Now it is guaranteed to be set
            guardian=validated_data.get("guardian"),
        )

        # Assign roles
        user.roles.set(Role.objects.filter(name__in=roles))
        return user


class BulkRegisterSerializer(serializers.Serializer):
    users = serializers.ListField(
        child=serializers.DictField(),
        allow_empty=False,
        help_text="A list of user registration data.",
    )

    def validate(self, data):
        """
        Validate bulk user data, ensuring unique emails and correct role assignments.
        """
        emails = [user_data["email"].lower()
                  for user_data in data["users"] if "email" in user_data]
        duplicate_emails = {
            email for email in emails if emails.count(email) > 1}

        if duplicate_emails:
            raise serializers.ValidationError(
                {"users": f"Duplicate emails found in the request: {', '.join(duplicate_emails)}"}
            )

        # Fetch all valid role names from the database in **lowercase**
        valid_roles = {role.lower()
                       for role in Role.objects.values_list("name", flat=True)}
        logger.debug(f"✅ Valid roles from DB: {valid_roles}")

        for idx, user_data in enumerate(data["users"]):
            roles = user_data.get("roles")

            # ✅ **Ensure roles exist in request (before reaching create method)**
            if roles is None or not roles:
                logger.error(f"❌ No roles provided for user {idx}")
                raise serializers.ValidationError(
                    {"roles": ["A user must have at least one role assigned."]}
                )

            if not isinstance(roles, list):
                logger.error(f"❌ Invalid roles format for user {idx}: {roles}")
                raise serializers.ValidationError(
                    {"roles": "Roles must be provided as a list."}
                )

            # Convert all roles to lowercase for comparison
            roles = [role.lower() for role in roles]

            # Validate roles against the database
            invalid_roles = [role for role in roles if role not in valid_roles]
            if invalid_roles:
                logger.error(
                    f"❌ Invalid roles for user {idx}: {invalid_roles}")
                raise serializers.ValidationError(
                    {"roles": f"Invalid roles provided: {', '.join(invalid_roles)}"}
                )

            # ✅ Ensure roles persist in data dictionary
            user_data["roles"] = roles

        return data

    def create(self, validated_data):
        """
        Bulk user creation logic with inline role handling and transaction safety.
        """
        users_data = validated_data["users"]
        created_users = []
        response_details = []

        logger.debug(f"📌 Users Data Before Creation: {users_data}")

        with transaction.atomic():
            for idx, user_data in enumerate(users_data):
                try:
                    logger.debug(f"📌 Processing user {idx}: {user_data}")

                    # Fetch Role objects from validated data
                    role_names = user_data.get("roles", [])
                    logger.debug(
                        f"📌 Roles received before DB query: {role_names}")

                    role_objects = Role.objects.filter(name__in=role_names)
                    if not role_objects.exists():
                        logger.error(
                            f"❌ Roles not found in the database for user {idx}: {role_names}"
                        )
                        raise serializers.ValidationError(
                            {"roles": f"Roles not found in the database: {role_names}"}
                        )

                    logger.debug(
                        f"✅ Roles matched in DB for user {idx}: {[role.name for role in role_objects]}")

                    # Create the user using RegisterSerializer
                    serializer = RegisterSerializer(data=user_data)
                    serializer.is_valid(raise_exception=True)
                    user = serializer.save()

                    # ✅ Assign roles AFTER user creation
                    user.roles.set(role_objects)

                    created_users.append(user)
                    response_details.append(
                        {
                            "email": user.email,
                            "status": "success",
                            "message": "User registered successfully.",
                        }
                    )

                except serializers.ValidationError as e:
                    logger.error(
                        f"❌ Validation error for user {idx}: {e.detail}")
                    response_details.append(
                        {
                            "email": user_data.get("email", "Unknown"),
                            "status": "failed",
                            "errors": e.detail,
                        }
                    )

                except Exception as e:
                    logger.error(
                        f"❌ Unexpected error for user {idx}: {str(e)}")
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
    appointment_time = serializers.SerializerMethodField()
    patient_details = serializers.SerializerMethodField()
    dentist_details = serializers.SerializerMethodField()

    class Meta:
        model = Appointment
        fields = [
            "id",
            "patient",
            "patient_details",
            "dentist",
            "dentist_details",
            "appointment_date",
            "appointment_time",
            "appointment_type",
            "reason_for_visit",
            "status",
            "notes",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def get_appointment_time(self, obj):
        """Extracts time from `appointment_date`."""
        return obj.appointment_date.strftime("%H:%M:%S") if obj.appointment_date else None

    def get_patient_details(self, obj):
        """Returns full patient details."""
        if not obj.patient:
            return None  # ✅ Prevents crashes when patient is missing

        return {
            "id": obj.patient.id,
            "name": f"{obj.patient.first_name} {obj.patient.last_name}",
            "email": obj.patient.email,
            "phone": obj.patient.contact_info,
            "date_of_birth": obj.patient.dob.strftime("%Y-%m-%d") if obj.patient.dob else None,
            "gender": obj.patient.gender,
            "address": getattr(obj.patient, "address", ""),
            "emergency_contact": {
                "name": getattr(obj.patient, "emergency_contact_name", ""),
                "phone": getattr(obj.patient, "emergency_contact_phone", ""),
            },
            "insurance_provider": getattr(obj.patient, "insurance_provider", None),
            "medical_history": obj.patient.medical_history.split(",") if hasattr(obj.patient, "medical_history") else [],
        }

    def get_dentist_details(self, obj):
        """Returns full dentist details."""
        if not obj.dentist:
            return None  # ✅ Prevents crashes when dentist is missing

        return {
            "id": obj.dentist.id,
            "name": f"{obj.dentist.first_name} {obj.dentist.last_name}",
            "specialty": getattr(obj.dentist, "specialty", ""),
            "email": obj.dentist.email,
            "phone": obj.dentist.contact_info,
            "license_number": getattr(obj.dentist, "license_number", ""),
            "years_of_experience": getattr(obj.dentist, "years_of_experience", 0),
            "clinic_address": getattr(obj.dentist, "clinic_address", ""),
            "available_slots": [
                {"date": slot.date.strftime(
                    "%Y-%m-%d"), "time": slot.time.strftime("%H:%M")}
                for slot in getattr(obj.dentist, "available_slots", [])
            ],
        }

    def validate_appointment_date(self, value):
        """Ensure the appointment date is not in the past."""
        if value.tzinfo is None:  # ✅ Only convert if it's naive
            value = make_aware(value)

        if value < timezone.now():
            raise serializers.ValidationError(
                "Appointment date cannot be in the past.")

        return value

    def validate(self, data):
        """Ensure patient and dentist are not the same."""
        patient = data.get("patient", getattr(self.instance, "patient", None))
        dentist = data.get("dentist", getattr(self.instance, "dentist", None))

        if patient and dentist and patient == dentist:
            raise serializers.ValidationError(
                "Patient and dentist cannot be the same person.")

        return data
