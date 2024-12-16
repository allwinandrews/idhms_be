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


class IsReceptionist(BasePermission):
    """
    Allows access only to Receptionist users.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "Receptionist"
