"""API endpoints for the home app."""

import logging
from ninja import Router, Schema
from django.http import HttpRequest
from ninja.responses import Response, codes_4xx
from devices.models import Device
from pki.models import CertificateModel, IssuingCaModel, DomainModel, BaseCaModel, IssuedDeviceCertificateModel
from pki import CaLocalization
from trustpoint.schema import ErrorSchema, SuccessSchema
from django.db.models import Count,F, Q,  Case, When, Value, IntegerField
from django.db.models.functions import TruncDate
from django.utils import timezone
from datetime import timedelta



log = logging.getLogger('tp.home')

router = Router()


def get_device_counts():
  """Get device counts from database"""
  device_counts = {}
  try:
    device_qr = Device.objects.values('device_onboarding_status').annotate(
      count=Count('device_onboarding_status')
    )
  except Exception as e:
    print(f"Error occurred in device count query: {e}")
  device_counts = {item['device_onboarding_status']: item['count'] for item in device_qr}

  # Set default value of 0 if status is not present
  for status, _ in Device.DeviceOnboardingStatus.choices:
    device_counts.setdefault(status, 0)

  device_counts['total'] = sum(device_counts.values())
  return device_counts

def get_cert_counts():
  """Get certificate counts from database"""
  cert_counts = {}
  # Get the current date and the dates for 7 days and 1 day ahead
  now = timezone.now()
  next_7_days = now + timedelta(days=7)
  next_1_day = now + timedelta(days=1)
  try:
    cert_counts = CertificateModel.objects.aggregate(
      total=Count('id'),
      active=Count('id', filter=Q(not_valid_after__gt=now)),
      expired=Count('id', filter=Q(not_valid_after__lt=now)),
      expiring_in_7_days=Count('id', filter=Q(not_valid_after__gt=now, not_valid_after__lte=next_7_days)),
      expiring_in_1_day=Count('id', filter=Q(not_valid_after__gt=now, not_valid_after__lte=next_1_day))
    )
  except Exception as e:
    print(f"Error occurred in certificate count query: {e}")
  return cert_counts

def get_issuing_ca_counts():
  """Get issuing CA counts from database"""
  # Current date
  today = timezone.now().date()
  issuing_ca_counts = {}
  try:
    # Query to get total, active, and expired Issuing CAs
    issuing_ca_counts = IssuingCaModel.objects.aggregate(
      total=Count('id'),

      active=Count(
        Case(
          When(issuing_ca_certificate__not_valid_after__gt=today, then=Value(1)),
          output_field=IntegerField()
        )
      ),

      expired=Count(
        Case(
          When(issuing_ca_certificate__not_valid_after__lte=today, then=Value(1)),
          output_field=IntegerField()
        )
      )
    )
  except Exception as e:
    print(f"Error occurred in issuing ca count query: {e}")

  return issuing_ca_counts

def get_device_counts_by_date_and_status():
  """Get device count by date and onboarding status from database"""
  device_counts_by_date_and_os = {}
  try:
    device_date_os_qr = Device.objects \
      .annotate(issue_date=TruncDate('created_at')) \
      .values('issue_date', onboarding_status=F('device_onboarding_status')) \
      .annotate(device_count=Count('id')) \
      .order_by('issue_date', 'device_onboarding_status')
  except Exception as e:
    print(f"Error occurred in device count by domain query: {e}")
  
  # Convert the queryset to a list
  device_counts_by_date_and_os = list(device_date_os_qr)
  #print("device_counts_by_date_and_os", device_counts_by_date_and_os)
  return device_counts_by_date_and_os

def get_device_count_by_onboarding_protocol():
  """Get device count by onboarding protocol from database"""
  device_op_counts = {str(status): 0 for _, status in Device.OnboardingProtocol.choices}
  try:
    device_op_qr = Device.objects.values('onboarding_protocol').annotate(
      count=Count('onboarding_protocol')
    )
  except Exception as e:
    print(f"Error occurred in device count by onboarding protocol query: {e}")
  # Mapping from short code to human-readable name
  protocol_mapping = {key: str(value) for key, value in Device.OnboardingProtocol.choices}
  device_op_counts = {
    protocol_mapping[item['onboarding_protocol']]: item['count']
    for item in device_op_qr
  }

  #device_op_counts['total'] = sum(device_op_counts.values())
  return device_op_counts

def get_device_count_by_domain():
  """Get device count by domain from database"""
  device_counts_by_domain = {}
  try:
    device_domain_qr = (
      DomainModel.objects
        .annotate(device_count=Count('device'))
        .values('unique_name', 'device_count')
    )
  except Exception as e:
    print(f"Error occurred in device count by domain query: {e}")
  
  # Convert the queryset to a list
  device_counts_by_domain = list(device_domain_qr)

  return device_counts_by_domain

def get_cert_counts_by_issuing_ca():
  """Get certificate count by issuing ca from database"""
  cert_counts_by_issuing_ca = {}
  try:
    cert_issuing_ca_qr = CertificateModel.objects \
      .annotate(cert_count=Count('issued_certificate_references')) \
      .filter(issuing_ca_model__isnull=False) \
      .values('cert_count', ca_name=F('issuing_ca_model__unique_name'))

     # Convert the queryset to a list
    cert_counts_by_issuing_ca = list(cert_issuing_ca_qr)
  except Exception as e:
    print(f"Error occurred in certificate count by issuing ca query: {e}")

  return cert_counts_by_issuing_ca

def get_cert_counts_by_issuing_ca_and_date():
  """Get certificate count by issuing ca from database"""
  cert_counts_by_issuing_ca_and_date = {}
  try:
    cert_issuing_ca_and_date_qr = CertificateModel.objects \
      .filter(issuer_references__issuing_ca_model__isnull=False) \
      .annotate(issue_date=TruncDate('added_at')) \
      .values('issue_date', name=F('issuing_ca_model__unique_name')) \
      .annotate(cert_count=Count('issued_certificate_references')) \
      .filter(name__isnull=False) \
      .order_by('added_at', 'name')

     # Convert the queryset to a list
    cert_counts_by_issuing_ca_and_date = list(cert_issuing_ca_and_date_qr)
    print("date", cert_counts_by_issuing_ca_and_date)
  except Exception as e:
    print(f"Error occurred in certificate count by issuing ca query: {e}")

  return cert_counts_by_issuing_ca_and_date

# def get_cert_counts_by_domain():
#   """Get certificate count by domain from database"""
#   cert_counts_by_domain = {}
#   try:
#     cert_domain_qr = DomainModel.objects \
#       .filter(issuing_ca__issuing_ca_certificate__isnull=False) \
#       .annotate(cert_count=Count('issuing_ca__issuing_ca_certificate__issued_certificate_references')) \
#       .values('unique_name', 'cert_count')
#      # Convert the queryset to a list
#     cert_counts_by_domain = list(cert_domain_qr)
#     #print("cert_counts_by_domain", cert_counts_by_domain)
#   except Exception as e:
#     print(f"Error occurred in certificate count by issuing ca query: {e}")

#   return cert_counts_by_domain

def get_cert_counts_by_domain():
  """Get certificate count by domain from database"""
  cert_counts_by_domain = {}
  try:
    cert_domain_qr = IssuedDeviceCertificateModel.objects \
      .values(unique_name=F('domain__unique_name')) \
      .annotate(cert_count=Count('domain')
    )
    
     # Convert the queryset to a list
    cert_counts_by_domain = list(cert_domain_qr)
    print("cert_counts_by_domain", cert_counts_by_domain)
  except Exception as e:
    print(f"Error occurred in certificate count by issuing ca query: {e}")
  return cert_counts_by_domain

def get_issuing_ca_counts_by_type():
  """Get issuing ca counts by type from database"""
  issuing_ca_type_counts = {str(type): 0 for _, type in CaLocalization.choices}
  try:
    ca_type_qr = BaseCaModel.objects.values('ca_localization').annotate(
      count=Count('ca_localization')
    )
  except Exception as e:
    print(f"Error occurred in ca counts by type query: {e}")
  # Mapping from short code to human-readable name
  protocol_mapping = {key: str(value) for key, value in CaLocalization.choices}
  issuing_ca_type_counts = {
    protocol_mapping[item['ca_localization']]: item['count']
    for item in ca_type_qr
  }

  #device_op_counts['total'] = sum(device_op_counts.values())
  return issuing_ca_type_counts


# --- PUBLIC HOME API ENDPOINTS ---
@router.get('/dashboard_data', exclude_none=True)
def dashboard_data(request: HttpRequest):
    """Get dashboard data for panels, tables and charts"""
    dashboard_data = {}

    ###### Get Device counts ######
    device_counts = get_device_counts()
    #print("device_counts", device_counts)

    dashboard_data["device_counts"] = device_counts

    ###### Get certificate counts ######
    cert_counts = get_cert_counts()
    #print("certificate_counts", cert_counts)
    if cert_counts:
      dashboard_data["cert_counts"] = cert_counts

    ###### Get Issuing CA counts ######
    issuing_ca_counts = get_issuing_ca_counts()

    #print("issuing_CA", issuing_ca_counts)
    if issuing_ca_counts:
      dashboard_data["issuing_ca_counts"] = issuing_ca_counts

    device_counts_by_date_and_os = get_device_counts_by_date_and_status()
    if device_counts_by_date_and_os:
      dashboard_data["device_counts_by_date_and_os"] = device_counts_by_date_and_os
    
    ###### Get device count by onboarding protocol ######
    device_counts_by_op = get_device_count_by_onboarding_protocol()
    print("device count by onboarding protocol", device_counts_by_op)
    if device_counts_by_op:
      dashboard_data["device_counts_by_op"] = device_counts_by_op

    ###### Get device count by domain ######
    device_counts_by_domain = get_device_count_by_domain()
    if device_counts_by_domain:
      dashboard_data["device_counts_by_domain"] = device_counts_by_domain
    
    ###### Get certificate count by issuing ca ######
    cert_counts_by_issuing_ca = get_cert_counts_by_issuing_ca()
    if cert_counts_by_issuing_ca:
      dashboard_data["cert_counts_by_issuing_ca"] = cert_counts_by_issuing_ca
    cert_counts_by_issuing_ca_and_date = get_cert_counts_by_issuing_ca_and_date()
    if cert_counts_by_issuing_ca_and_date:
      dashboard_data["cert_counts_by_issuing_ca_and_date"] = cert_counts_by_issuing_ca_and_date
    
    cert_counts_by_domain = get_cert_counts_by_domain()
    if cert_counts_by_domain:
      dashboard_data["cert_counts_by_domain"] = cert_counts_by_domain
    issuing_ca_counts_by_type = get_issuing_ca_counts_by_type()
    print("issuing ca count by type", issuing_ca_counts_by_type)
    if issuing_ca_counts_by_type:
      dashboard_data["ca_counts_by_type"] = issuing_ca_counts_by_type
    return Response(dashboard_data)

