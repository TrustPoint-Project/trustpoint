from pyasn1.type import univ, namedtype, namedval, tag, constraint, useful, char
from pyasn1_modules import rfc2459, rfc4210

class PKIHeader(univ.Sequence):
    """
    PKIHeader ::= SEQUENCE {
    pvno                INTEGER     { cmp1999(1), cmp2000(2) },
    sender              GeneralName,
    recipient           GeneralName,
    messageTime     [0] GeneralizedTime         OPTIONAL,
    protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
    senderKID       [2] KeyIdentifier           OPTIONAL,
    recipKID        [3] KeyIdentifier           OPTIONAL,
    transactionID   [4] OCTET STRING            OPTIONAL,
    senderNonce     [5] OCTET STRING            OPTIONAL,
    recipNonce      [6] OCTET STRING            OPTIONAL,
    freeText        [7] PKIFreeText             OPTIONAL,
    generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
                     InfoTypeAndValue     OPTIONAL

    ______ Added id-it OIDs ________
    certProfile     [21]  SEQUENCE SIZE (1..MAX) OF
                    UTF8String            OPTIONAL
    }

    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'pvno', univ.Integer(
                namedValues=namedval.NamedValues(('cmp1999', 1), ('cmp2000', 2))
            )
        ),
        namedtype.NamedType('sender', rfc2459.GeneralName()),
        namedtype.NamedType('recipient', rfc2459.GeneralName()),
        namedtype.OptionalNamedType('messageTime', useful.GeneralizedTime().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('protectionAlg', rfc2459.AlgorithmIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('senderKID', rfc2459.KeyIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('recipKID', rfc2459.KeyIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('transactionID', univ.OctetString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
        namedtype.OptionalNamedType('senderNonce', univ.OctetString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
        namedtype.OptionalNamedType('recipNonce', univ.OctetString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
        namedtype.OptionalNamedType('freeText', rfc4210.PKIFreeText().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 7))),
        namedtype.OptionalNamedType('generalInfo',
                                    univ.SequenceOf(
                                        componentType=rfc4210.InfoTypeAndValue().subtype(
                                            sizeSpec=constraint.ValueSizeConstraint(1, rfc4210.MAX)
                                        )
                                    ).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8))
        ),
        namedtype.OptionalNamedType('certProfile',
                                    univ.SequenceOf(
                                        componentType=char.UTF8String()
                                    ).subtype(
                                        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 21))
                                    )
    )
