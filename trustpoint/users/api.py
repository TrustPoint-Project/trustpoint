import base64

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from ninja import Router, Schema
from ninja.security import django_auth
from trustpoint.schema import ErrorSchema, SuccessSchema
from users.models import PersonalAccessToken

router = Router()

class LoginBodySchema(Schema):
    username: str
    password: str

class LoginPATSchema(Schema):
    success: bool
    pat: str

@router.post("/login", response={200: LoginPATSchema, 403: ErrorSchema}, auth=None)
def login(request, data: LoginBodySchema):
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

@router.post("/logout", response={200: SuccessSchema, 422: ErrorSchema})
def logout(request, all: bool = False):
    """Logout endpoint for the API
    
    Deletes the personal access token from the user.
    If option "all" is set, all PATs for the user are deleted.
    Does nothing without "all" in case of django_auth.
    """
    if isinstance(request.auth, User):
        if all:
            PersonalAccessToken.objects.filter(user=request.auth).delete()
        else:
            return 422, {'error': 'No PAT provided'}
    elif isinstance(request.auth, PersonalAccessToken):
        if all:
            user = request.auth.user
            PersonalAccessToken.objects.filter(user=user).delete()
        else:
            request.auth.delete()
    else:
        return 422, {'error': 'Unkown auth method'}

    return 200, {'success': True}