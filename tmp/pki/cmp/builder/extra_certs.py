from pyasn1.type import univ, tag
from pyasn1_modules import rfc2459, rfc4210
from pyasn1.codec.der import decoder
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate

class ExtraCerts:
    """
    A class to manage extra certificates in a CMP message.

    Attributes:
        extra_certs (SequenceOf): The sequence of extra certificates.
    """
    def __init__(self):
        """
        Initializes the ExtraCerts with an empty sequence of CMPCertificates.
        """
        self.extra_certs = univ.SequenceOf(componentType=rfc4210.CMPCertificate()).subtype(
             sizeSpec=rfc4210.constraint.ValueSizeConstraint(1, rfc4210.MAX),
             explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
         )

    def generate_sequence(self, extra_certs):
        for cert in extra_certs:
            self.add_certificate(cert)
        extraCerts_sequence = self.get_extra_certs()

        if not isinstance(extraCerts_sequence, univ.SequenceOf):
            raise TypeError("The extra certificates should be a sequence.")
        if any(not isinstance(cert, rfc4210.CMPCertificate) for cert in extraCerts_sequence):
            raise ValueError("All items in extraCerts must be CMPCertificates.")

        return extraCerts_sequence

    def add_certificate(self, cert: Certificate):
        """
        Adds a certificate to the extra certificates sequence.

        :param cert: Certificate, the certificate to add
        """

        der_cert = cert.public_bytes(encoding=Encoding.DER)
        cert_decode, _ = decoder.decode(der_cert, asn1Spec=rfc2459.Certificate())

        cmp_cert = rfc4210.CMPCertificate()
        cmp_cert.setComponentByName("tbsCertificate", cert_decode['tbsCertificate'])
        cmp_cert.setComponentByName("signatureValue", cert_decode['signatureValue'])
        cmp_cert.setComponentByName("signatureAlgorithm", cert_decode['signatureAlgorithm'])

        self.extra_certs.append(cmp_cert)

    def get_extra_certs(self) -> univ.SequenceOf:
        """
        Returns the sequence of extra certificates.

        :return: univ.SequenceOf, the sequence of extra certificates
        """
        return self.extra_certs

class caPubs:
    """
    A class to manage CA public certificates in a CMP message.

    Attributes:
        ca_certs (SequenceOf): The sequence of CA public certificates.
    """
    def __init__(self):
        """
        Initializes the caPubs with an empty sequence of CMPCertificates.
        """
        self.ca_certs = univ.SequenceOf(componentType=rfc4210.CMPCertificate()).subtype(
             sizeSpec=rfc4210.constraint.ValueSizeConstraint(1, rfc4210.MAX),
             explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
         )

    def add_certificate(self, cert: Certificate):
        """
        Adds a CA certificate to the sequence.

        :param cert: Certificate, the certificate to add
        """

        der_cert = cert.public_bytes(encoding=Encoding.DER)
        cert_decode, _ = decoder.decode(der_cert, asn1Spec=rfc2459.Certificate())

        cmp_cert = rfc4210.CMPCertificate()
        cmp_cert.setComponentByName("tbsCertificate", cert_decode['tbsCertificate'])
        cmp_cert.setComponentByName("signatureValue", cert_decode['signatureValue'])
        cmp_cert.setComponentByName("signatureAlgorithm", cert_decode['signatureAlgorithm'])

        self.ca_certs.append(cmp_cert)

    def get_ca_cert(self) -> univ.SequenceOf:
        """
        Returns the sequence of CA certificates.

        :return: univ.SequenceOf, the sequence of CA certificates
        """
        return self.ca_certs