"""API endpoints for the devices app."""
from __future__ import annotations

import logging

from django.http import HttpRequest  # noqa: TCH002
from django.utils.translation import gettext_lazy as _
from ninja import Router, Schema
from pki import CertificateStatus, CertificateTypes

from devices import OnboardingProtocol
from devices.models import Device
from trustpoint.schema import ErrorSchema, SuccessSchema

router = Router()
log = logging.getLogger('tp.devices')


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
    serial_number: str = ''
    onboarding_protocol: OnboardingProtocol


class DeviceUpdateSchema(Schema):
    """Schema for updating an existing device."""

    name: str
    serial_number: str


def device_api_dict(dev: Device) -> dict:
    """Gets a dict with device details corresponding to DeviceInfoSchema."""
    return {
        'id': dev.pk,
        'name': dev.device_name,
        'serial_number': dev.device_serial_number,
        # TODO(Air): Prefer using the enum key instead of the label
        # (e.g. so that we can change the label for i18n without breaking the API)
    }


@router.get('/domain-certificates/{device_id}/{domain_id}/', summary='Get domain certificates')
def get_domain_certificates(request, device_id: int, domain_id: int) -> dict:
    """Retrieve active certificates for a specific domain and device.

    Args:
        request: HTTP request object.
        device_id (int): ID of the device.
        domain_id (int): ID of the domain.

    Returns:
        dict: A dictionary containing active certificates.
    """
    device = Device.get_by_id(device_id)
    if not isinstance(device, Device):
        msg = _('No device with id %s found') % device_id
        log.info(msg)
        return {'certificates': []}

    domain = device.get_domain(domain_id)
    certs = device.get_all_active_certs_by_domain(domain)

    certificates = [
        {
            'type': issued_cert.certificate_type,
            'expiration_date': issued_cert.certificate.not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
            'status': CertificateStatus(issued_cert.certificate.certificate_status).label,
            'revoke_url': f'/onboarding/revoke/{issued_cert.certificate.pk}/'
        }
        for category in ['ldevids', 'other']
        for issued_cert in certs.get(category, [])
    ]

    return {'certificates': certificates}


@router.get('/certificate-types/', summary='Get certificate types')
def get_certificate_types(request) -> dict:
    """Retrieve all available certificate types.

    Args:
        request: HTTP request object.

    Returns:
        dict: A dictionary containing available certificate types.
    """
    _ = request
    return {'types': [{'value': ct.value, 'label': ct.label} for ct in CertificateTypes]}


@router.get('/onboarding-methods/', summary='Get onboarding methods')
def get_onboarding_methods(request):
    """Retrieve all supported onboarding procedures.

    Args:
        request: HTTP request object.

    Returns:
        dict: A dictionary containing supported onboarding methods.
    """
    _ = request
    return {'methods': [{'value': op.value, 'label': op.label} for op in OnboardingProtocol]}


@router.get('/', response=list[DeviceInfoSchema], exclude_none=True)
def devices(request: HttpRequest) -> list[dict]:
    """Retrieve a list of all devices.

    Args:
        request (HttpRequest): HTTP request object.

    Returns:
        list[dict]: A list of dictionaries containing device details.
    """
    _ = request
    qs = Device.objects.all()
    return [device_api_dict(dev) for dev in qs]


@router.get('/{device_id}', response={200: DeviceInfoSchema, 404: ErrorSchema}, exclude_none=True)
def device(request: HttpRequest, device_id: int) -> tuple[int, dict]:
    """Retrieve details about a specific device by ID.

    Args:
        request (HttpRequest): HTTP request object.
        device_id (int): ID of the device.

    Returns:
        tuple[int, dict]: HTTP status code and device details or an error message.
    """
    _ = request
    dev = Device.get_by_id(device_id)
    if not dev:
        return 404, {'error': 'Device not found.'}

    return 200, device_api_dict(dev)


@router.post('/', response={201: DeviceInfoSchema, 400: ErrorSchema}, exclude_none=True)
def create_device(request: HttpRequest, data: DeviceCreateSchema) -> tuple[int, dict]:
    """Creates a new device."""
    _ = request
    dev = Device(device_name=data.name, serial_number=data.serial_number, onboarding_protocol=data.onboarding_protocol)
    # TODO(Air): Set domain
    # TODO(Air): String validation (e.g. not empty, max. length)
    dev.save()
    return 201, device_api_dict(dev)


@router.patch('/{device_id}', response={200: DeviceInfoSchema, 404: ErrorSchema, 422: ErrorSchema}, exclude_none=True)
def update_device(request: HttpRequest, device_id: int, data: DeviceUpdateSchema) -> tuple[int, dict]:
    """Updates a device with a given ID."""
    _ = request
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
def delete_device(request: HttpRequest, device_id: int) -> tuple[int, dict]:
    """Deletes a device with a given ID."""
    _ = request
    dev = Device.get_by_id(device_id)
    if not dev:
        return 404, {'error': 'Device not found.'}

    dev.delete()
    return 200, {'success': True}
