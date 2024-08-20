from pyasn1_modules import rfc4210
from pyasn1.codec.der import encoder, decoder
import logging
from pki.pki.cmp.errorhandling.pki_failures import (
    SystemFailure
)
from pyasn1.type import univ, namedtype, tag


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# pyasn1_modules has a wrong object definition for genp (Defined as gen)
class PKIBody(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('genp', rfc4210.GenRepContent().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 22)
            ))
    )

class PKIMessageCreator:
    """
    A class to create PKI messages with the specified body, header, and protection mechanisms.
    """
    def __init__(self, pki_body: univ.Sequence, pki_header: univ.Sequence, pki_body_type: object, response_protection: object, extraCerts: univ.Sequence = None):
        """
        Initialize the PKIMessageCreator.

        Args:
            pki_body (univ.Sequence): The PKI body.
            pki_header (univ.Sequence): The PKI header.
            pki_body_type (object): The PKI body type information.
            response_protection (object): The protection mechanism.
            extraCerts (univ.Sequence, optional): List of extra certificates. Defaults to None.
        """
        self.pki_body = pki_body
        self.pki_header = pki_header
        self.pki_body_type = pki_body_type
        self.response_protection = response_protection
        self.extraCerts = extraCerts

        logger.info("PKIMessageCreator initialized.")

    def create_pki_message(self) -> bytes:
        """
        Create the PKI message.

        Returns:
            bytes: Encoded PKI message.
        """
        try:
            response = rfc4210.PKIMessage()

            response.setComponentByName('header', self.pki_header)
            response.setComponentByName('body', self.pki_body)

            if self.extraCerts is not None:
                response.setComponentByName('extraCerts', self.extraCerts)


            response.setComponentByName('protection', self.response_protection)

            response_data = encoder.encode(response)

            decoded_data, _ = decoder.decode(response_data, asn1Spec=rfc4210.PKIMessage())

            logger.info("PKI message created successfully.")
            return response_data
        except Exception as e:
            logger.error("Error creating PKI message: %s", e)
            raise SystemFailure("Failed to create PKI message") from e

