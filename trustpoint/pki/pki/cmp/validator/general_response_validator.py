from pyasn1.type import univ
from . import BadMessageCheck, GetCACertsValidator


class GenpValidator:
    def __init__(self, body: univ.Sequence):
        """
        Initializes the generic genp validator with the genp body.

        Args:
        - body (univ.Sequence): The body of the genp response message as an ASN.1 sequence.
        """
        self.body = body
        self.oid = None
        self.validators = {
            univ.ObjectIdentifier('1.3.6.1.5.5.7.4.17'): self._validate_ca_certs,  # OID for caCerts
            univ.ObjectIdentifier('1.3.6.1.5.5.7.4.19'): self._validate_cert_req_template, # OID for certReqTemplate
            univ.ObjectIdentifier('1.3.6.1.5.5.7.4.20'): self._validate_root_ca_certs,  # OID for rootCaCert
            univ.ObjectIdentifier('1.3.6.1.5.5.7.4.23'): self._validate_crls # OID for crls
        }

    def validate(self):
        """
        Validates the 'genp' response based on the OID found in the body.

        Returns:
        - bool: True if the 'genp' response is valid, False otherwise.
        - list: A list of validation error messages if the 'genp' response is invalid.
        """
        self._get_oid()

        if self.oid in self.validators:
            validator_function = self.validators[self.oid]
            return validator_function()
        else:
            raise BadMessageCheck(f"No validator found for OID {self.oid}")

    def _get_oid(self):
        """
        Extracts the OID from the body of the genp response.

        Raises:
        - BadMessageCheck: If the OID is not present or invalid.
        """
        if not 'gen' in self.body:
            BadMessageCheck("GenRepContent is missing from the  body.")

        if 'infoType' in self.body.getComponentByName('gen')[0]:
            self.oid = self.body.getComponentByName('gen')[0]['infoType']
            print(f"OID PARAM: {self.oid}")
        else:
            raise BadMessageCheck("OID (infoType) is missing from the genp body.")

    def _validate_ca_certs(self):
        """
        Validator for the caCerts OID (1.3.6.1.5.5.7.4.17).

        Returns:
        - bool: True if the caCerts validation is successful.

        Raises:
        - BadMessageCheck: If the caCerts validation fails.
        """
        ca_certs_validator = GetCACertsValidator(self.body)
        ca_certs_validator.validate()
        return True

    def _validate_cert_req_template(self):
        """
        Validator for certReqTemplate.
        """
        # TODO: Implement logic - Validator for the certReqTemplate
        pass

    def _validate_root_ca_certs(self):
        """
        Validator for rootCaCert.
        """
        # TODO: Implement logic - Validator for the rootCaCert
        pass

    def _validate_crls(self):
        """
        Validator for crls.
        """
        # TODO: Implement logic - Validator for the crls
        pass

