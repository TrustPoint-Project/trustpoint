"""Main list of Django Ninja API routers"""

from ninja import NinjaAPI
from onboarding.api import router as onboarding_router

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie

api = NinjaAPI()


api.add_router('/pki/', 'pki.api.router')
api.add_router('/onboarding/', onboarding_router)

@api.post("/csrf")
@ensure_csrf_cookie
@csrf_exempt
def get_csrf_token(request):
    return HttpResponse()