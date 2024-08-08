"""API endpoints for the onboarding app."""

# ruff: noqa: ANN201 # no need to annotate return type which is always "-> tuple[int, dict] | HttpResponse"
# ruff: noqa: ARG001 # "request" argument is not used in many endpoints, but required for compatibility

from __future__ import annotations

# import base64
#
# from devices.models import Device
# from django.http import HttpRequest, HttpResponse
from ninja import Router, Schema

# from onboarding.crypto_backend import CryptoBackend as Crypt
# from onboarding.models import (
#     DownloadOnboardingProcess,
#     ManualOnboardingProcess,
#     OnboardingProcess,
#     OnboardingProcessState,
# )
# from trustpoint.schema import ErrorSchema, SuccessSchema

router = Router()
