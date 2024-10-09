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

@router.get('/dashboard_data', exclude_none=True)
def dashboard_data(request: HttpRequest):
    """Get dashboard data for panels, tables and charts"""
    device_qr = Device.objects.values('device_onboarding_status').annotate(count=Count('device_onboarding_status'))
    device_counts = {item['device_onboarding_status']: item['count'] for item in device_qr}

    # Set default value of 0 if status is not present
    for status, _ in Device.DeviceOnboardingStatus.choices:
      device_counts.setdefault(status, 0)

    device_counts['total'] = sum(device_counts.values())
    #print("dev", device_counts)

    dash_data = {"device_counts": device_counts}
    return Response(dash_data)