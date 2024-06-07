"""Main list of Django Ninja API routers"""

from __future__ import annotations

from ninja import NinjaAPI
from ninja.security import HttpBearer, django_auth
from devices.api import router as devices_router
from onboarding.api import router as onboarding_router
from users.api import router as users_router
from users.models import PersonalAccessToken


class AuthBearer(HttpBearer):
    """Bearer token authentication for the API"""
    def authenticate(self, request, token) -> PersonalAccessToken | None:
        """Check the provided token against the database for validity"""
        return PersonalAccessToken.get_from_string(token)


api = NinjaAPI(
    auth=(AuthBearer(), django_auth),
    title='Trustpoint API',
    version='0.1.0'
)

api.add_router('/devices/', devices_router, tags=['Devices'])
api.add_router('/onboarding/', onboarding_router, tags=['Onboarding'])
# api.add_router('/pki/', 'pki.api.router', tags=['PKI'])
api.add_router('/users/', users_router, tags=['Users'])

# TODO(Air): Couldn't get non-GET requests to work with CSRF using Django-auth reliably
# Therefore a simple bearer personal access token login system is implemented for now with a separate /login endpoint
# We should decide on some suitable API authentication methods
# Options include:
# - Bearer token (PAT partially implemented)
# - JWT or other token-based auth like OAuth2
# - Basic auth
# - Client certificates (preferred)
