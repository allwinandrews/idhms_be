from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.roles.filter(name="admin").exists()
        )


class IsPatient(BasePermission):
    """
    Allows access only to patient users.
    """

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.roles.filter(name="patient").exists()
        )


class IsDentist(BasePermission):
    """
    Allows access only to dentist users.
    """

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.roles.filter(name="dentist").exists()
        )


class IsReceptionist(BasePermission):
    # Custom permission to allow access only to users with the receptionist role.

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.roles.filter(name="receptionist").exists()
        )
