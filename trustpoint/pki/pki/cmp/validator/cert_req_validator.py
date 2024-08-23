
from pyasn1_modules import rfc5280

from . import BadMessageCheck



class CertificateReqValidator:

    def __init__(self, cmp_body):

        self.cmp_body = cmp_body
        self.cert_req_validator = CertReqValidator(self.cmp_body)

    def validate(self):
        self.cert_req_validator.validate_cr()


class InitializationReqValidator:

    def __init__(self, cmp_body):
        self.cmp_body = cmp_body
        self.cert_req_validator = CertReqValidator(self.cmp_body)

    def validate(self):
        self.cert_req_validator.validate_ir()

class KeyUpdateReqValidator:

    def __init__(self, cmp_body):
        self.cmp_body = cmp_body
        self.cert_req_validator = CertReqValidator(self.cmp_body)

    def validate(self):
        # TODO: The certificate the EE wishes to update MUST NOT be expired or
        #       revoked and MUST have been issued by the addressed CA.
        # TODO: A new public-private key pair should be used.
        self.cert_req_validator.validate_kur()


class CertReqValidator:
    def __init__(self, cmp_body):
        """
        Initializes the validator with ASN.1 encoded data.

        Args:
        - cmp_body (bytes): The ASN.1 encoded CMP body.
        """
        self.cmp_body = cmp_body
        self._request = None
        self._ir = None
        self._cr = None
        self._kur = None
        self._certReqMsg = None
        self._certReq = None
        self._certTemplate = None
        self._popo = None

    @property
    def ir(self):
        return self._ir

    @property
    def cr(self):
        return self._cr

    @property
    def kur(self):
        return self._kur

    @property
    def certReq(self):
        return self._certReq

    @property
    def certTemplate(self):
        return self._certTemplate

    @property
    def popo(self):
        return self._popo

    def validate_ir(self):
        """
        Validates the decoded CMP body according to the specified requirements.

        Returns:
        - bool: True if the ir CMP body is valid, False otherwise.
        - list: A list of validation error messages if the body is invalid.
        """

        self._validate_request_ir()
        self._validate_cert_req()
        self._validate_cert_template()
        self._validate_popo()

    def validate_cr(self):
        """
        Validates the decoded cr CMP body according to the specified requirements.

        Returns:
        - bool: True if the CMP body is valid, False otherwise.
        - list: A list of validation error messages if the body is invalid.
        """

        self._validate_request_cr()
        self._validate_cert_req()
        self._validate_cert_template()
        self._validate_popo()

    def validate_kur(self):
        """
        Validates the decoded kur CMP body according to the specified requirements.

        Returns:
        - bool: True if the CMP body is valid, False otherwise.
        - list: A list of validation error messages if the body is invalid.
        """

        self._validate_request_kur()
        self._validate_cert_req()
        self._validate_cert_template()
        self._validate_popo()


    def _validate_request_ir(self):
        """
        Validates the 'ir' field of the CMP body.
        """
        self._ir = self.cmp_body['ir']
        self._request = self._ir
        if not self._ir or len(self._ir) != 1:
            raise BadMessageCheck("The 'ir' field is required and must contain exactly one 'CertReqMsg'.")

    def _validate_request_cr(self):
        """
        Validates the 'cr' field of the CMP body.
        """
        self._cr = self.cmp_body['cr']
        self._request = self._cr
        if not self._cr or len(self._cr) != 1:
            raise BadMessageCheck("The 'cr' field is required and must contain exactly one 'CertReqMsg'.")

    def _validate_request_kur(self):
        """
        Validates the 'kur' field of the CMP body.
        """
        self._kur = self.cmp_body['kur']
        self._request = self._kur
        if not self._kur or len(self._kur) != 1:
            raise BadMessageCheck("The 'kur' field is required and must contain exactly one 'CertReqMsg'.")

    def _validate_cert_req(self):
        """
        Validates the 'certReq' field within the 'ir' field.
        """
        self._certReqMsg = self._request[0]
        self._certReq = self._request[0]['certReq']
        certReqId = self._certReq['certReqId']

        if certReqId != 0:
            raise BadMessageCheck("The 'certReqId' field is required and must be 0.")

    def _validate_cert_template(self):
        """
        Validates the 'certTemplate' field within the 'certReq' field.
        """
        self._certTemplate = self._certReq['certTemplate']

        version = self._certTemplate['version']
        if version.hasValue() and int(version) != 2:
            raise BadMessageCheck("The 'version' field, if present, must be 2.")

        subject = self._certTemplate['subject']
        if not subject.hasValue():
            raise BadMessageCheck("The 'subject' field is required.")

        extensions = self._certTemplate['extensions']
        subjectAltName_present = False


        if extensions.hasValue():
            for extension in extensions:
                if extension['extnID'] == rfc5280.id_ce_subjectAltName:
                    subjectAltName_present = True
                    break

        #if subjectAltName_present and subject != univ.Null('NULL-DN'):
        #    self.errors.append("The 'subject' field must be NULL-DN if subjectAltName extension is present.")

        publicKey = self._certTemplate['publicKey']
        if publicKey.hasValue():
            if not publicKey['algorithm'].hasValue():
                raise BadMessageCheck("The 'algorithm' field in 'publicKey' is required if local key generation is used.")

            subjectPublicKey = publicKey['subjectPublicKey']
            if not subjectPublicKey.hasValue():
                raise BadMessageCheck("The 'subjectPublicKey' field in 'publicKey' is required.")
            elif len(subjectPublicKey) == 0 and not self.cmp_body.get('centralKeyGeneration', False):
                raise BadMessageCheck("The 'subjectPublicKey' field must be non-zero-length if local key generation is used.")

    def _validate_popo(self):
        """
        Validates the 'popo' (Proof of Possession) field within the 'certReq' field.
        """
        self._popo = self._certReqMsg['pop'] # for CMP according to RFC 4210
        #self._popo = self._certReq['popo'] # for Lightweight CMP according to RFC 9483

        centralKeyGeneration = False
        localKeyGeneration = False

        # TODO: How do I identity that centralKeyGeneration or localKeyGeneration is used
        #       -- MUST be present if local key generation is used
        #       -- MUST be absent if central key generation is requested

        if centralKeyGeneration or localKeyGeneration:
            if self._popo.hasValue():
                raise BadMessageCheck("The 'popo' field must be absent if central key generation is requested.")
        else:
            if not self._popo.hasValue():
                raise BadMessageCheck("The 'popo' field is required if local key generation is used.")
            else:
                if not self._popo['signature'].hasValue():
                    raise BadMessageCheck("The 'signature' field in 'popo' is required if the key can be used for signing.")
                if not self._popo['signature']['algorithmIdentifier'].hasValue():
                    raise BadMessageCheck("The 'algorithmIdentifier' field in 'popo' is required.")
                if 'poposkInput' in self._popo and self._popo['poposkInput'].hasValue():
                    raise BadMessageCheck("The 'poposkInput' field in 'popo' must not be used.")