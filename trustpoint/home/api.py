"""API endpoints for the home app."""

import logging
from ninja import Router, Schema
from django.http import HttpRequest
from ninja.responses import Response, codes_4xx
from devices.models import Device
from trustpoint.schema import ErrorSchema, SuccessSchema
from django.db.models import Count


log = logging.getLogger('tp.home')

router = Router()

# --- PUBLIC HOME API ENDPOINTS ---

@router.get('/device-count', exclude_none=True)
def device_count(request: HttpRequest):
    """Get devices count by their onboarding status."""
    device_qr = Device.objects.values('device_onboarding_status').annotate(count=Count('device_onboarding_status'))
    device_counts = {item['device_onboarding_status']: item['count'] for item in device_qr}

    # Set default value of 0 if status is not present
    for status, _ in Device.DeviceOnboardingStatus.choices:
      device_counts.setdefault(status, 0)

    device_counts['total'] = sum(device_counts.values())
    #print("dev", device_counts)
    return Response(device_counts)