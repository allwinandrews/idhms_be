from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    """
    Allows access only to Admin users.
    """

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.roles.filter(name="Admin").exists()
        )


class IsPatient(BasePermission):
    """
    Allows access only to Patient users.
    """

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.roles.filter(name="Patient").exists()
        )


class IsDentist(BasePermission):
    """
    Allows access only to Dentist users.
    """

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.roles.filter(name="Dentist").exists()
        )


class IsReceptionist(BasePermission):
    # Custom permission to allow access only to users with the Receptionist role.

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.roles.filter(name="Receptionist").exists()
        )
