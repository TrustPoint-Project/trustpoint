"""API endpoints for the users app."""

# ruff: noqa: ANN201 # no need to annotate return type which is always "-> tuple[int, dict] | HttpResponse"
# ruff: noqa: ARG001 # "request" argument is not used in many endpoints, but required for compatibility

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.http import HttpRequest
from ninja import Router, Schema

from trustpoint.schema import ErrorSchema, SuccessSchema
from users.models import PersonalAccessToken

router = Router()

class LoginBodySchema(Schema):
    """Schema for the login endpoint input body."""
    username: str
    password: str

class LoginPATSchema(Schema):
    """Schema for the login endpoint response upon successful login."""
    success: bool
    pat: str

@router.post('/login', response={200: LoginPATSchema, 403: ErrorSchema}, auth=None, exclude_none=True)
def login(request: HttpRequest, data: LoginBodySchema):
    """Username/password login endpoint for the API

    Creates a new personal access token for the user and returns it.
    """
    # TODO(Air): Needs rate-limiting, PAT scoping, etc.
    user = authenticate(request, username=data.username, password=data.password)
    if user is not None:
        pat = PersonalAccessToken(user=user)
        pat.save()
        return 200, {'success': True, 'pat': pat.token}
    return 403, {'error': 'Login failed'}

@router.post('/logout', response={200: SuccessSchema, 422: ErrorSchema}, exclude_none=True)
def logout(request: HttpRequest, invalidate_all: bool = False): # noqa: FBT001, FBT002
    """Logout endpoint for the API

    Deletes the personal access token from the user.
    If option "invalidate_all" is set, all PATs for the user are deleted.
    Does nothing without "invalidate_all" in case of django_auth.
    """
    if isinstance(request.auth, User):
        if invalidate_all:
            PersonalAccessToken.objects.filter(user=request.auth).delete()
        else:
            return 422, {'error': 'No PAT provided'}
    elif isinstance(request.auth, PersonalAccessToken):
        if invalidate_all:
            user = request.auth.user
            PersonalAccessToken.objects.filter(user=user).delete()
        else:
            request.auth.delete()
    else:
        return 422, {'error': 'Unkown auth method'}

    return 200, {'success': True}
