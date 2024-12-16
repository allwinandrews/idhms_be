from rest_framework import serializers
from api.models import User
import re
from datetime import date


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "role"]


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration with validation for email, phone number, and date of birth.
    """

    phone_number = serializers.CharField(max_length=15, required=True)
    email = serializers.EmailField(required=True)
    dob = serializers.DateField(required=True)

    class Meta:
        model = User
        fields = ["username", "password", "role", "email", "phone_number", "dob"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate_phone_number(self, value):
        """
        Validate phone number format.
        Example: +1234567890 or 1234567890
        """
        if not re.match(r"^\+?\d{10,15}$", value):
            raise serializers.ValidationError("Phone number must be 10-15 digits.")
        return value

    def validate_dob(self, value):
        """
        Validate that the date of birth is in the past.
        """
        if value >= date.today():
            raise serializers.ValidationError("Date of birth must be in the past.")
        return value

    def validate_username(self, value):
        """
        Validate that the username is unique.
        """
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists.")
        return value

    def validate_email(self, value):
        """
        Validate that the email is unique.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def create(self, validated_data):
        """
        Create a new user instance with the validated data.
        """
        user = User.objects.create_user(
            username=validated_data["username"],
            password=validated_data["password"],
            role=validated_data.get("role", "Receptionist"),
            email=validated_data["email"],
            dob=validated_data["dob"],
            contact_info=validated_data["phone_number"],
        )
        return user
