from django.db import models
from django.utils.translation import gettext_lazy as _


class CertificateStatus(models.TextChoices):
    """CertificateModel status"""
    OK = 'OK', _('OK')
    REVOKED = 'REV', _('Revoked')
    EXPIRED = 'EXP', _('Expired')
    NOT_YET_VALID = 'NYV', _('Not Yet Valid')


class CaLocalization(models.TextChoices):
    """The localization of the CA.

    Auto-Gen PKI is a special case of the local CA, where the root CA is self-signed by the system.
    """
    LOCAL = "local", _('Local')
    REMOTE = "remote", _('Remote')
    AUTO_GEN_PKI = "autogen", _('AutoGenPKI')


class CertificateTypes(models.TextChoices):
    LDEVID = 'LDevID', _('LDevID')
    APPLICATION = 'Application', _('Application')


class TemplateName(models.TextChoices):
    GENERIC = 'Generic', _('Generic')
    TLSSERVER = 'TLS-Server', _('TLS Server')
    TLSCLIENT = 'TLS-Client', _('TLS Client')
