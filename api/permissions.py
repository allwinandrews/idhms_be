from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    """
    Allows access only to Admin users.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "Admin"


class IsPatient(BasePermission):
    """
    Allows access only to Patient users.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "Patient"


class IsDentist(BasePermission):
    """
    Allows access only to Dentist users.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "Dentist"


from rest_framework.permissions import BasePermission


class IsReceptionist(BasePermission):
    # Custom permission to allow access only to users with the Receptionist role.

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "Receptionist"
