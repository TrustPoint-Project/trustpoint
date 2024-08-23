from pyasn1_modules import rfc2459, rfc4210
from pyasn1.type import univ, tag, char
from pyasn1.codec.der import decoder

from .. import GenpValidator, InitializationRespValidator, CertificationRespValidator, \
    KeyUpdateRespValidator, RevocationRespValidator, UnacceptedPolicy, caPubs, ErrorValidator

from ..validator import GenpValidator

class PkiBodyCreator:
    """
    A class to create various CMP responses, including CertRepMessage, ErrorMsgContent, and RevRepContent.

    Attributes:
        cert_req_id (univ.Integer): The certificate request ID.
        pki_body_choice (univ.Sequence): The PKI body choice for the response.
        int_fail (int): The integer failure code.
        str_fail (str): The string failure description.
        ca_pubs (univ.SequenceOf): The CA public certificates.
        pki_status_info (rfc4210.PKIStatusInfo): The PKI status information.
    """

    def __init__(self):
        self.cert_req_id = None
        self.pki_body = None
        self.pki_body_choice = None
        self.pki_body_type = None
        self.int_fail = None
        self.str_fail = None
        self.ca_pubs = None
        self.pki_status_info = None

    def set_body_type(self, pki_body_type):
        """
        Sets the pki body type and response class based on the request short name.

        :param response_class: The class of the response for the current request.
        """
        self.pki_body_type = pki_body_type
        self.pki_body_choice = pki_body_type.response_class


    def set_cert_req_id(self, cert_req_id: univ.Integer):
        """
        Sets the certificate request ID.

        :param cert_req_id: univ.Integer, the certificate request ID
        :raises ValueError: If cert_req_id is not an instance of univ.Integer
        """
        if not isinstance(cert_req_id, univ.Integer):
            raise ValueError(f"Expected pyasn1.type.univ.Integer, got {type(cert_req_id).__name__}")
        self.cert_req_id = cert_req_id

    def create_status_info(self, int_status: int):
        """
        Creates the PKIStatusInfo structure.

        :param int_status: int, the integer status to set
        :raises UnacceptedPolicy: If the response type is not supported
        """
        if isinstance(self.pki_body_choice, (rfc4210.CertRepMessage, rfc4210.ErrorMsgContent, rfc4210.KeyRecRepContent, rfc4210.GenRepContent)):
            self.pki_status_info = rfc4210.PKIStatusInfo()

            pki_status = self.create_pki_status(int_status)
            self.pki_status_info.setComponentByName('status', pki_status)
        elif isinstance(self.pki_body_choice, rfc4210.RevRepContent):
            self.pki_body_choice['status'][0]['status'] = int_status
        else:
            raise UnacceptedPolicy("Response not supported")

        if self.int_fail:
            fail_info = self.create_fail_info()
            self.pki_status_info.setComponentByName('failInfo', fail_info)

        if self.str_fail:
            pki_freetext= rfc4210.PKIFreeText()
            self.str_fail = pki_freetext.setComponentByPosition(0, char.UTF8String(self.str_fail))

    def create_fail_info(self) -> rfc4210.PKIFailureInfo:
        """
        Creates the PKIFailureInfo structure.

        :return: rfc4210.PKIFailureInfo, the failure info
        """
        fail_info = rfc4210.PKIFailureInfo(self.int_fail)
        return fail_info

    def create_pki_status(self, int_status: int) -> rfc4210.PKIStatus:
        """
        Creates the PKIStatus structure.

        :param int_status: int, the integer status to set
        :return: rfc4210.PKIStatus, the PKI status
        """

        status = rfc4210.PKIStatus(int_status)
        return status

    def decode_certificate(self, cert_pem: bytes) -> rfc2459.Certificate:
        """
        Decodes a PEM-encoded certificate.

        :param cert_pem: bytes, the PEM-encoded certificate
        :return: rfc2459.Certificate, the decoded certificate
        """
        certificate, _ = decoder.decode(cert_pem, asn1Spec=rfc2459.Certificate())
        return certificate

    def create_cert_or_enc_cert(self, certificate: rfc2459.Certificate) -> rfc4210.CertOrEncCert:
        """
        Creates the CertOrEncCert structure.

        :param certificate: rfc2459.Certificate, the certificate to include
        :return: rfc4210.CertOrEncCert, the CertOrEncCert structure
        """

        cmp_cert = rfc4210.CMPCertificate().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        cmp_cert.setComponentByName("tbsCertificate", certificate['tbsCertificate'])
        cmp_cert.setComponentByName("signatureValue", certificate['signatureValue'])
        cmp_cert.setComponentByName("signatureAlgorithm", certificate['signatureAlgorithm'])
        cert_or_enc_cert = rfc4210.CertOrEncCert()
        cert_or_enc_cert['certificate'] = cmp_cert
        return cert_or_enc_cert

    def create_certified_key_pair(self, cert_or_enc_cert: rfc4210.CertOrEncCert) -> rfc4210.CertifiedKeyPair:
        """
        Creates the CertifiedKeyPair structure.

        :param cert_or_enc_cert: rfc4210.CertOrEncCert, the CertOrEncCert structure to include
        :return: rfc4210.CertifiedKeyPair, the CertifiedKeyPair structure
        """
        certified_key_pair = rfc4210.CertifiedKeyPair()
        certified_key_pair.setComponentByName('certOrEncCert', cert_or_enc_cert)
        return certified_key_pair

    def set_fail(self, int_fail: int = None, str_fail: str = None):
        """
        Sets the failure information.

        :param int_fail: int, the integer failure code
        :param str_fail: str, the string failure description
        """
        self.int_fail = int_fail
        self.str_fail = str_fail

    def set_info_value(self, info_type_and_value):
        """
        Sets the info value in the PKI body choice.

        :param info_type_and_value: The info value to set.
        """
        self.pki_body_choice.setComponentByPosition(0, info_type_and_value)

    def add_ca_pub(self, ca_cert: bytes):
        """
        Adds a CA certificate to the CA publications.

        :param ca_cert: bytes, the PEM-encoded CA certificate
        :raises TypeError: If the CA publications are not a sequence
        :raises ValueError: If any item in caPubs is not a CMPCertificate
        """
        ca_certs_instance = caPubs()
        ca_certs_instance.add_certificate(ca_cert)
        self.ca_pubs = ca_certs_instance.get_ca_cert()

        if not isinstance(self.ca_pubs, univ.SequenceOf):
            raise TypeError("The CA certificates should be a sequence.")
        if any(not isinstance(cert, rfc4210.CMPCertificate) for cert in self.ca_pubs):
            raise ValueError("All items in caPubs must be CMPCertificates.")

    def _validate_body(self):
        """
        Validates the PKI body based on the response short name.
        """
        validators = {
            "ip": InitializationRespValidator,
            "cp": CertificationRespValidator,
            "kup": KeyUpdateRespValidator,
            "rp": RevocationRespValidator,
            "gen": GenpValidator,
            "error": ErrorValidator
        }

        validator_class = validators.get(self.pki_body_type.response_short_name)
        if validator_class:
            validator = validator_class(self.pki_body)
            validator.validate()

    def create_pki_body_choice(self, cert_pem):
        """
        Creates the PKI body choice based on the response type.

        :param cert_pem: bytes, the PEM-encoded certificate to include.
        :return: univ.Sequence, the PKI body choice.
        """
        if isinstance(self.pki_body_choice, rfc4210.CertRepMessage):
            self._create_cert_rep_message(cert_pem)
        elif isinstance(self.pki_body_choice, rfc4210.RevRepContent):
            pass
        elif isinstance(self.pki_body_choice, rfc4210.GenRepContent):
            pass
        elif isinstance(self.pki_body_choice, rfc4210.ErrorMsgContent):
            self._create_error_message()

        return self.pki_body_choice

    def _create_cert_rep_message(self, cert_pem):
        """
        Creates a CertRepMessage structure.

        :param cert_pem: bytes, the PEM-encoded certificate to include.
        """
        cert_response_content = rfc4210.CertResponse()
        cert_response_content.setComponentByName('certReqId', self.cert_req_id)
        cert_response_content.setComponentByName('status', self.pki_status_info)

        if cert_pem:
            certificate = self.decode_certificate(cert_pem)
            cert_or_enc_cert = self.create_cert_or_enc_cert(certificate)
            certified_key_pair = self.create_certified_key_pair(cert_or_enc_cert)
            cert_response_content.setComponentByName('certifiedKeyPair', certified_key_pair)

        self.pki_body_choice.setComponentByName('response', univ.SequenceOf(
            componentType=rfc4210.CertResponse()).setComponentByPosition(0, cert_response_content))

        if self.ca_pubs:
            self.pki_body_choice.setComponentByName('caPubs', self.ca_pubs)

    def _create_error_message(self):
        """
        Creates an ErrorMsgContent structure.
        """
        self.pki_body_choice.setComponentByName('pKIStatusInfo', self.pki_status_info)
        self.pki_body_choice.setComponentByName('errorCode', self.int_fail)
        self.pki_body_choice.setComponentByName('errorDetails', self.str_fail)

    def create_pki_body(self, int_status: int = 0, cert_pem: bytes = None) -> univ.Sequence:
        """
        Creates the PKIBody structure based on the response type.

        :param int_status: int, the integer status to set.
        :param cert_pem: bytes, the PEM-encoded certificate to include.
        :return: rfc4210.PKIBody, the created PKIBody structure.
        """
        self.create_status_info(int_status)
        self.create_pki_body_choice(cert_pem)

        if not isinstance(self.pki_body_choice, type(self.pki_body_type.response_class)):
            raise ValueError(
                f"Expected {type(self.pki_body_type.response_class)}, got {type(self.pki_body_choice).__name__}")

        self.pki_body = rfc4210.PKIBody()
        self.pki_body.setComponentByName(self.pki_body_type.response_short_name, self.pki_body_choice)

        self._validate_body()

        return self.pki_body



