"""Module to handle revocation logic for devices and device credentials."""

from devices.models import IssuedCredentialModel
from pki.models.certificate import RevokedCertificateModel


class DeviceCredentialRevocation:

    @staticmethod
    def revoke_certificate(issued_credential_id, reason) -> bool:
        # issued_credential = IssuedCredentialModel.objects.select_related(
        #     'credential__primarycredentialcertificate_set__certificate'
        # ).get(id=issued_credential_id)
        issued_credential = IssuedCredentialModel.objects.get(id=issued_credential_id)

        #primary_cert = issued_credential.credential.primarycredentialcertificate_set.filter(is_primary=True).first()
        primary_cert = issued_credential.credential.certificate

        if primary_cert and not hasattr(primary_cert, 'revocation'):
            RevokedCertificateModel.objects.create(
                certificate=primary_cert,
                revocation_reason=reason
            )
            return True

        return False  # Already revoked or not found
