from pyasn1.codec.ber import decoder
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from pyasn1_modules import rfc2511, rfc2459
from pyasn1.codec.der.encoder import encode
from cryptography.x509.oid import NameOID
from pki.pki.cmp.errorhandling.pki_failures import (
    BadMessageCheck, SystemFailure, BadPOP
)


class PoPVerifier:
    def __init__(self, pki_message, pki_body_type):
        self.pki_message = pki_message
        self.pki_body_type = pki_body_type
        self.header = pki_message.getComponentByName('header')
        self.body = pki_message.getComponentByName('body')


    def verify(self):

        if not isinstance(self.body.getComponentByName(self.pki_body_type.request_short_name), rfc2511.CertReqMessages):
            return False

        self.extra_certs = self.pki_message.getComponentByName('extraCerts')
        self.cert_req_message = self.body.getComponentByName(self.pki_body_type.request_short_name).getComponentByPosition(0)

        popo = self.cert_req_message.getComponentByName('pop')
        if popo is None:
            raise BadPOP("Proof of possesion is missing")

        pop_type = popo.getName()
        if pop_type == 'signature':
            return self.verify_pop_signature(popo)
        elif pop_type == 'keyEncipherment':
            pass
        elif pop_type == 'keyAgreement':
            pass
        else:
            return False

    def verify_pop_signature(self, popo):
        popo_sig_key = popo.getComponentByName('signature')
        algorithm_identifier = popo_sig_key.getComponentByName('algorithmIdentifier')
        signature_bytes = popo_sig_key.getComponentByName('signature').asOctets()

        cert_req = self.cert_req_message.getComponentByName('certReq')
        tbs_cert_req_bytes = encode(cert_req)
        public_key = self.get_public_key_from_cert_template(cert_req)

        #cert_template_subject = self.get_subject_name(cert_template.getComponentByName('subject'))
        #cmp_cert_subject = cert.subject

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature_bytes,
                    tbs_cert_req_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                print("Signature verification succeeded")
            else:
                raise BadMessageCheck("Public key is not an RSA public key")
        except InvalidSignature as e:
            raise BadPOP("Signature of proof of possesion is invalid")
        except Exception as e:
            raise SystemFailure(f"Unexpected error while verifing the proof of possesion: {e}")

    def extract_certificate(self):
        if self.extra_certs and len(self.extra_certs) > 0:
            cert = self.extra_certs[0]
            return encode(cert)
        return None

    def print_public_key(self, public_key):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(f"Public Key ():\n{pem.decode('utf-8')}")

    def get_public_key_from_cert_template(self, cert_req):
        cert_template = cert_req.getComponentByName('certTemplate')
        cert_template_public_key = cert_template.getComponentByName('publicKey')
        public_key_bytes = cert_template_public_key.getComponentByName('subjectPublicKey').asOctets()
        return serialization.load_der_public_key(public_key_bytes, backend=default_backend())


    def get_subject_name(self, subject_asn1):
        # Convert the ASN.1 subject to a cryptography.x509.Name object
        subject_name = []
        for rdn in subject_asn1[0]:
            for atv in rdn:

                oid = atv.getComponentByName('type')
                value = atv.getComponentByName('value')

                value, _ = decoder.decode(bytes(value))

                # print(f"OID: {oid} ({len(oid)}), Value: >{str(value)}< ({len(str(value))})")
                if oid == rfc2459.id_at_commonName:
                    subject_name.append(x509.NameAttribute(NameOID.COMMON_NAME, str(value)))
                elif oid == rfc2459.id_at_countryName:
                    subject_name.append(x509.NameAttribute(NameOID.COUNTRY_NAME, str(value)))
                elif oid == rfc2459.id_at_stateOrProvinceName:
                    subject_name.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, str(value)))
                elif oid == rfc2459.id_at_localityName:
                    subject_name.append(x509.NameAttribute(NameOID.LOCALITY_NAME, str(value)))
                elif oid == rfc2459.id_at_organizationName:
                    subject_name.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, str(value)))
                elif oid == rfc2459.id_at_organizationalUnitName:
                    subject_name.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, str(value)))

        subject = x509.Name(subject_name)

        return subject