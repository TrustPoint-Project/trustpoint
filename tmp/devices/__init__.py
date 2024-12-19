from django.db import models
from django.utils.translation import gettext_lazy as _


class CertificateTypes(models.TextChoices):
    LDEVID = 'LDevID', _('LDevID')
    APPLICATION = 'Application', _('Application')


class TemplateName(models.TextChoices):
    GENERIC = 'Generic', _('Generic')
    TLSSERVER = 'TLS-Server', _('TLS Server')
    TLSCLIENT = 'TLS-Client', _('TLS Client')