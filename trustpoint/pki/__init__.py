from django.db import models
from django.utils.translation import gettext_lazy as _


class ReasonCode(models.TextChoices):
    """Revocation reasons per RFC 5280"""
    UNSPECIFIED = 'unspecified', _('Unspecified')
    KEY_COMPROMISE = 'keyCompromise', _('Key Compromise')
    CA_COMPROMISE = 'cACompromise', _('CA Compromise')
    AFFILIATION_CHANGED = 'affiliationChanged', _('Affiliation Changed')
    SUPERSEDED = 'superseded', _('Superseded')
    CESSATION = 'cessationOfOperation', _('Cessation of Operation')
    CERTIFICATE_HOLD = 'certificateHold', _('Certificate Hold')
    PRIVILEGE_WITHDRAWN = 'privilegeWithdrawn', _('Privilege Withdrawn')
    AA_COMPROMISE = 'aACompromise', _('AA Compromise')
    REMOVE_FROM_CRL = 'removeFromCRL', _('Remove from CRL')


class CertificateStatus(models.TextChoices):
    """CertificateModel status"""
    OK = 'O', _('OK')
    REVOKED = 'R', _('Revoked')
    # EXPIRED = 'E', _('Expired')
    # NOT_YET_VALID = 'N', _('Not Yet Valid')


class CaLocalization(models.TextChoices):
    """The localization of the CA.

    Auto-Gen PKI is a special case of the local CA, where the root CA is self-signed by the system."""
    LOCAL = "L", _('Local')
    REMOTE = "R", _('Remote')
    AUTO_GEN_PKI = "A", _('AutoGenPKI')


class CertificateTypes(models.TextChoices):
    LDEVID = 'LDevID', _('LDevID')
    APPLICATION = 'Application', _('Application')


class TemplateName(models.TextChoices):
    GENERIC = 'Generic', _('Generic')
    TLSSERVER = 'TLS_Server', _('TLS Server')
    
