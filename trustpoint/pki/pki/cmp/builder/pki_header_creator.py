from pyasn1_modules import rfc2459, rfc4210
from pyasn1.type import univ, char, useful, tag, constraint
import datetime
import os
from cryptography import x509
from cryptography.x509 import NameOID
import logging

from pki.pki.cmp.asn1_modules import CertProfileOids
from pki.pki.cmp.validator.header_validator import GenericHeaderValidator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PKIHeaderCreator:
    """
    A class to create a PKIHeader for the PKIMessage.
    """
    def __init__(self, incoming_header: rfc4210.PKIHeader, issuing_ca_object):
        """
        Initialize the PKIHeaderCreator with the incoming header and CA certificate.

        :param incoming_header (rfc4210.PKIHeader): The incoming PKIHeader.
        :param issuing_ca_object: The IssuingCa object of the domain
        """
        self.incoming_header = incoming_header
        self.issuing_ca_object = issuing_ca_object
        self.ca_cert = issuing_ca_object.get_issuing_ca_certificate_serializer().as_crypto()

        self.pki_header = rfc4210.PKIHeader()
        self.pki_header.setComponentByName('pvno', 2)
        logger.info("PKIHeaderCreator initialized.")


    def create_header(self) -> rfc4210.PKIHeader:
        """
        Creates and returns the PKIHeader.

        :return: rfc4210.PKIHeader, the created PKIHeader
        """
        self.set_recipient()
        self.set_sender()
        self.set_message_time()
        self.set_sender_kid()
        self.set_recip_kid()
        self.set_transaction_id()
        self.set_protection_alg()
        self.set_sender_nonce()
        self.set_recip_nonce()
        logger.info("PKIHeader created.")
        validate_header = GenericHeaderValidator(self.pki_header)
        validate_header.validate()
        return self.pki_header


    def set_recipient(self):
        """
        Sets the recipient in the PKIHeader.
        """
        recipient = self.incoming_header.getComponentByName('sender')
        self.pki_header.setComponentByName('recipient', recipient)

    def set_recip_nonce(self):
        """
        Sets the recipient nonce in the PKIHeader.
        """
        sender_nonce = self.incoming_header.getComponentByName('senderNonce')

        if sender_nonce.hasValue():
            recip_nonce = univ.OctetString(sender_nonce).subtype(
                 explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
            self.pki_header.setComponentByName('recipNonce', recip_nonce)

    def set_sender_nonce(self):
        """
        Sets the sender nonce in the PKIHeader with 128 bits of (pseudo-) random data.
        """
        # Generate 128 bits (16 bytes) of random data
        sender_nonce_value = os.urandom(16)

        # Create an OctetString with the random data and set it as senderNonce
        sender_nonce = univ.OctetString(sender_nonce_value).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
        )

        self.pki_header.setComponentByName('senderNonce', sender_nonce)

    def set_protection_alg(self):
        """
        Sets the protection algorithm in the PKIHeader.
        """
        protectionAlg = self.incoming_header.getComponentByName('protectionAlg')

        #pbm_params, _ = decoder.decode(protectionAlg.getComponentByName('parameters'), asn1Spec=rfc2459.AlgorithmIdentifier())

        self.pki_header.setComponentByName('protectionAlg', protectionAlg)

    def set_cert_template(self, profiles: list):

        profile_seq = univ.SequenceOf(componentType=char.UTF8String())

        for profile in profiles:
            profile_seq.append(char.UTF8String(profile))

        info_type_and_value = rfc4210.InfoTypeAndValue().subtype(
            sizeSpec=constraint.ValueSizeConstraint(1, rfc4210.MAX)
        )
        info_type_and_value.setComponentByName('infoType', CertProfileOids.id_certProfile)  # Set the infoType
        info_type_and_value.setComponentByName('infoValue', profile_seq)

        general_info = univ.SequenceOf(componentType=rfc4210.InfoTypeAndValue().subtype(
            sizeSpec=constraint.ValueSizeConstraint(1, rfc4210.MAX)
        )
        ).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8))

        general_info.append(info_type_and_value)

        self.pki_header.setComponentByName('generalInfo', general_info)

    def set_sender(self):
        """
        Sets the sender in the PKIHeader.
        """
        sender = rfc2459.GeneralName()

        directory_name = rfc2459.Name().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))
        rdn_sequence = rfc2459.RDNSequence()


        for i, attribute in enumerate(self.ca_cert.subject):
            rdn = rfc2459.RelativeDistinguishedName()

            rfc_oid = None
            if attribute.oid == NameOID.COUNTRY_NAME:
                rfc_oid = rfc2459.id_at_countryName
            elif attribute.oid == NameOID.STATE_OR_PROVINCE_NAME:
                rfc_oid = rfc2459.id_at_stateOrProvinceName
            elif attribute.oid == NameOID.LOCALITY_NAME:
                rfc_oid = rfc2459.id_at_localityName
            elif attribute.oid == NameOID.ORGANIZATION_NAME:
                rfc_oid = rfc2459.id_at_organizationName
            elif attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                rfc_oid = rfc2459.id_at_organizationalUnitName
            elif attribute.oid == NameOID.COMMON_NAME:
                rfc_oid = rfc2459.id_at_commonName
            else:
                raise ValueError("OID of subject issuer is not supported")

            if rfc_oid:
                atv = rfc2459.AttributeTypeAndValue().setComponentByName('type', rfc_oid)
                atv.setComponentByName('value', char.PrintableString(attribute.value))
                rdn.setComponentByPosition(0, atv)
                rdn_sequence.setComponentByPosition(i, rdn)

        directory_name.setComponentByPosition(0, rdn_sequence)

        sender.setComponentByName('directoryName', directory_name)

        self.pki_header.setComponentByName('sender', sender)

    def set_message_time(self):
        """
        Sets the message time in the PKIHeader.
        """
        current_time = datetime.datetime.now(datetime.UTC).strftime('%Y%m%d%H%M%SZ')
        message_time = useful.GeneralizedTime(current_time).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
        self.pki_header.setComponentByName('messageTime', message_time)

    def set_sender_kid(self):
        """
        Sets the sender key identifier in the PKIHeader.
        """

        ski = self.ca_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
        sender_kid = univ.OctetString(ski).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )
        self.pki_header.setComponentByName('senderKID', sender_kid)

    def set_recip_kid(self):
        """
        Sets the recipient key identifier in the PKIHeader.
        """
        sender_kid = self.incoming_header.getComponentByName('senderKID')
        if sender_kid.hasValue():
            recip_kid = sender_kid.subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            )
            self.pki_header.setComponentByName('recipKID', recip_kid)

    def set_transaction_id(self):
        """
        Sets the transaction ID in the PKIHeader.
        """
        transaction_id = self.incoming_header.getComponentByName('transactionID')
        if transaction_id is not None:
            self.pki_header.setComponentByName('transactionID', transaction_id)

