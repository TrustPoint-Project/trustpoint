"""API endpoints for the devices app."""

from ninja import Router, Schema
from django.http import HttpRequest
from devices import DeviceOnboardingStatus
from devices.models import Device

from devtools import debug

from trustpoint.schema import ErrorSchema, SuccessSchema

router = Router()


class DeviceInfoSchema(Schema):
    """Schema for the device information."""
    id: int
    name: str
    serial_number: str
    onboarding_protocol: str
    onboarding_status: str


class DeviceCreateSchema(Schema):
    """Schema for creating a new device."""
    name: str
    serial_number: str = ""
    onboarding_protocol: Device.OnboardingProtocol


class DeviceUpdateSchema(Schema):
    """Schema for updating an existing device."""
    name: str = None
    serial_number: str = None


def device_api_dict(dev: Device) -> dict:
    """Gets a dict with device details corresponding to DeviceInfoSchema."""
    return {
        'id': dev.id,
        'name': dev.device_name,
        'serial_number': dev.device_serial_number,
        # TODO(Air): Prefer using the enum key instead of the label
        # (e.g. so that we can change the label for i18n without breaking the API)
        'onboarding_protocol': str(Device.OnboardingProtocol(dev.onboarding_protocol).label),
        'onboarding_status': str(DeviceOnboardingStatus(dev.device_onboarding_status).label)
    }


@router.get('/', response=list[DeviceInfoSchema], exclude_none=True)
def devices(request: HttpRequest):
    """Get a list of all devices."""
    qs = Device.objects.all()
    response = []
    for dev in qs:
        response.append(device_api_dict(dev))
    return response


@router.get('/{device_id}', response={200: DeviceInfoSchema, 404: ErrorSchema}, exclude_none=True)
def device(request: HttpRequest, device_id: int):
    """Returns details about a device with a given ID."""
    dev = Device.get_by_id(device_id)
    if not dev:
        return 404, {'error': 'Device not found.'}
    
    return 200, device_api_dict(dev)


@router.post('/', response={201: DeviceInfoSchema, 400: ErrorSchema}, exclude_none=True)
def create_device(request: HttpRequest, data: DeviceCreateSchema):
    """Creates a new device."""
    dev = Device(
        device_name=data.name,
        serial_number=data.serial_number,
        onboarding_protocol=data.onboarding_protocol)
    # TODO(Air): Set domain
    # TODO(Air): String validation (e.g. not empty, max. length)
    dev.save()
    return 201, device_api_dict(dev)


@router.patch('/{device_id}', response={200: DeviceInfoSchema, 404: ErrorSchema, 422: ErrorSchema}, exclude_none=True)
def update_device(request: HttpRequest, device_id: int, data: DeviceUpdateSchema):
    """Updates a device with a given ID."""
    dev = Device.get_by_id(device_id)
    if not dev:
        return 404, {'error': 'Device not found.'}
    
    if data.name:
        dev.device_name = data.name

    if data.serial_number:
        if dev.device_serial_number:
            return 422, {'error': 'Serial number cannot be changed once set.'}
        dev.device_serial_number = data.serial_number

    dev.save()
    return 200, device_api_dict(dev)


@router.delete('/{device_id}', response={200: SuccessSchema, 404: ErrorSchema}, exclude_none=True)
def delete_device(request: HttpRequest, device_id: int):
    """Deletes a device with a given ID."""
    dev = Device.get_by_id(device_id)
    if not dev:
        return 404, {'error': 'Device not found.'}
    
    dev.delete()
    return 200, {'success': True}
