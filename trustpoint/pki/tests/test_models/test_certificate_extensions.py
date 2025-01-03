import hashlib

import pytest  # type: ignore  # noqa: PGH003
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ExtendedKeyUsageOID

# Aus Ihrem Projekt
from pki.models.certificate import CertificateModel
from pki.tests import (
    DNS_NAME_VALUE,
    IP_ADDRESS_VALUE,
    ORGANIZATION_NAME,
    OTHER_NAME_CONTENT,
    OTHER_NAME_OID,
    REGISTERED_ID_OID,
    RFC822_EMAIL,
    URI_VALUE,
)
from pki.tests.fixtures import self_signed_cert_with_ext  # noqa: F401
from pyasn1.codec.der.decoder import decode  # type: ignore  # noqa: PGH003
from pyasn1.type import char  # type: ignore  # noqa: PGH003


@pytest.mark.django_db
def test_key_usage_ext(self_signed_cert_with_ext) -> None:
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    kue = cert_model.key_usage_extension
    assert kue is not None
    assert kue.digital_signature is True
    assert kue.content_commitment is True
    assert kue.key_encipherment is True
    assert kue.data_encipherment is True
    assert kue.key_agreement is True
    assert kue.key_cert_sign is True
    assert kue.crl_sign is True
    assert kue.encipher_only is True
    assert kue.decipher_only is True


@pytest.mark.django_db
def test_san_ext(self_signed_cert_with_ext) -> None:
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    san_ext = cert_model.subject_alternative_name_extension
    assert san_ext is not None
    san = san_ext.subject_alt_name

    # DNS
    assert any(d.value == DNS_NAME_VALUE for d in san.dns_names.all())
    # RFC822
    assert any(r.value == RFC822_EMAIL for r in san.rfc822_names.all())
    # URI
    assert any(u.value == URI_VALUE for u in san.uniform_resource_identifiers.all())
    # DirectoryName
    assert san.directory_names.count() == 1
    dir_name = san.directory_names.first()
    assert any(attr.value == ORGANIZATION_NAME for attr in dir_name.names.all())
    # RegisteredID
    assert any(r.value == REGISTERED_ID_OID for r in san.registered_ids.all())
    # IPAddress
    assert any(ip.value == IP_ADDRESS_VALUE for ip in san.ip_addresses.all())
    # OtherName
    assert san.other_names.count() == 1
    other_name = san.other_names.first()
    assert other_name.type_id == OTHER_NAME_OID
    decoded_asn1, _ = decode(bytes.fromhex(other_name.value), asn1Spec=char.UTF8String())
    assert str(decoded_asn1) == OTHER_NAME_CONTENT


@pytest.mark.django_db
def test_ian_ext(self_signed_cert_with_ext) -> None:
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    ian_ext = cert_model.issuer_alternative_name_extension
    assert ian_ext is not None
    ian = ian_ext.issuer_alt_name

    # DNS
    assert any(d.value == DNS_NAME_VALUE for d in ian.dns_names.all())
    # RFC822
    assert any(r.value == RFC822_EMAIL for r in ian.rfc822_names.all())
    # URI
    assert any(u.value == URI_VALUE for u in ian.uniform_resource_identifiers.all())
    # DirectoryName
    assert ian.directory_names.count() == 1
    dir_name = ian.directory_names.first()
    assert any(attr.value == ORGANIZATION_NAME for attr in dir_name.names.all())
    # RegisteredID
    assert any(r.value == REGISTERED_ID_OID for r in ian.registered_ids.all())
    # IP
    assert any(ip.value == IP_ADDRESS_VALUE for ip in ian.ip_addresses.all())
    # OtherName
    assert ian.other_names.count() == 1
    other_name = ian.other_names.first()
    assert other_name.type_id == OTHER_NAME_OID
    decoded_asn1, _ = decode(bytes.fromhex(other_name.value), asn1Spec=char.UTF8String())
    assert str(decoded_asn1) == OTHER_NAME_CONTENT


@pytest.mark.django_db
def test_basic_constraints_ext(self_signed_cert_with_ext) -> None:
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    bce = cert_model.basic_constraints_extension
    assert bce is not None
    assert bce.ca is True
    assert bce.path_length_constraint == 0


@pytest.mark.django_db
def test_authority_key_identifier_ext(self_signed_cert_with_ext) -> None:
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    aki_ext = cert_model.authority_key_identifier_extension
    assert aki_ext is not None

    # Schlüssel-ID
    public_key = self_signed_cert_with_ext.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expected_key_identifier = hashlib.sha1(public_key_bytes).digest().hex().upper()
    assert aki_ext.key_identifier == expected_key_identifier

    # Serial
    expected_serial_number = hex(self_signed_cert_with_ext.serial_number)[2:].upper()
    assert aki_ext.authority_cert_serial_number == expected_serial_number

    # Issuer
    authority_cert_issuer = aki_ext.authority_cert_issuer
    assert any(r.value == RFC822_EMAIL for r in authority_cert_issuer.rfc822_names.all())
    assert any(d.value == DNS_NAME_VALUE for d in authority_cert_issuer.dns_names.all())
    assert any(u.value == URI_VALUE for u in authority_cert_issuer.uniform_resource_identifiers.all())
    assert authority_cert_issuer.directory_names.count() == 1
    dir_name = authority_cert_issuer.directory_names.first()
    assert any(attr.value == ORGANIZATION_NAME for attr in dir_name.names.all())
    assert any(r.value == REGISTERED_ID_OID for r in authority_cert_issuer.registered_ids.all())
    assert any(ip.value == IP_ADDRESS_VALUE for ip in authority_cert_issuer.ip_addresses.all())

    # OtherName
    assert authority_cert_issuer.other_names.count() == 1
    other_name = authority_cert_issuer.other_names.first()
    assert other_name.type_id == OTHER_NAME_OID
    decoded_asn1, _ = decode(bytes.fromhex(other_name.value), asn1Spec=char.UTF8String())
    assert str(decoded_asn1) == OTHER_NAME_CONTENT


@pytest.mark.django_db
def test_subject_key_identifier_ext(self_signed_cert_with_ext) -> None:
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    ski_ext = cert_model.subject_key_identifier_extension
    assert ski_ext is not None

    public_key = self_signed_cert_with_ext.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expected_key_identifier = hashlib.sha1(public_key_bytes).digest().hex().upper()
    assert ski_ext.key_identifier == expected_key_identifier


@pytest.mark.django_db
def test_certificate_policies_multiple_entries(self_signed_cert_with_ext) -> None:
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    policies_ext = cert_model.certificate_policies_extension
    assert policies_ext is not None
    assert policies_ext.critical is True
    assert policies_ext.certificate_policies.count() == 2

    # EV
    ev_policy = policies_ext.certificate_policies.filter(policy_identifier="2.23.140.1.1").first()
    assert ev_policy is not None
    assert ev_policy.policy_qualifiers.count() == 2

    ev_cps_uri = ev_policy.policy_qualifiers.filter(qualifier__cps_uri__cps_uri="https://example-ev-certs.com/cps").first()
    assert ev_cps_uri is not None

    ev_user_notice = ev_policy.policy_qualifiers.filter(qualifier__user_notice__explicit_text__contains="EV certificates issued").first()
    assert ev_user_notice is not None

    # DV
    dv_policy = policies_ext.certificate_policies.filter(policy_identifier="2.23.140.1.2.1").first()
    assert dv_policy is not None
    assert dv_policy.policy_qualifiers.count() == 2

    dv_cps_uri = dv_policy.policy_qualifiers.filter(qualifier__cps_uri__cps_uri="https://example-dv-certs.com/cps").first()
    assert dv_cps_uri is not None

    dv_user_notice = dv_policy.policy_qualifiers.filter(qualifier__user_notice__explicit_text__contains="DV certificates issued").first()
    assert dv_user_notice is not None


@pytest.mark.django_db
def test_extended_key_usage_ext(self_signed_cert_with_ext) -> None:
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    eku_ext = cert_model.extended_key_usage_extension
    assert eku_ext is not None
    assert eku_ext.critical is False

    expected_oids = {
        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
        ExtendedKeyUsageOID.CODE_SIGNING.dotted_string,
        ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string,
        ExtendedKeyUsageOID.TIME_STAMPING.dotted_string,
        ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string,
    }
    saved_oids = {kp.oid for kp in eku_ext.key_purpose_ids.all()}
    assert saved_oids == expected_oids


@pytest.mark.django_db
def test_name_constraints_ext(self_signed_cert_with_ext) -> None:
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    nc_ext = cert_model.name_constraints_extension
    assert nc_ext is not None
    assert nc_ext.critical is True

    # permittedSubtrees
    assert nc_ext.permitted_subtrees.count() == 3
    assert any(st.rfc822_name.value == RFC822_EMAIL if st.rfc822_name else False
               for st in nc_ext.permitted_subtrees.all())
    assert any(st.dns_name.value == DNS_NAME_VALUE if st.dns_name else False
               for st in nc_ext.permitted_subtrees.all())
    assert any(st.uri.value == URI_VALUE if st.uri else False
               for st in nc_ext.permitted_subtrees.all())

    # excludedSubtrees
    assert nc_ext.excluded_subtrees.count() == 3
    excluded_directory = nc_ext.excluded_subtrees.filter(directory_name__isnull=False).first()
    assert excluded_directory is not None
    assert any(attr.value == ORGANIZATION_NAME for attr in excluded_directory.directory_name.names.all())

    assert any(st.registered_id.value == REGISTERED_ID_OID if st.registered_id else False
               for st in nc_ext.excluded_subtrees.all())

    excluded_other_name = nc_ext.excluded_subtrees.filter(other_name__isnull=False).first()
    assert excluded_other_name is not None
    assert excluded_other_name.other_name.type_id == OTHER_NAME_OID
    from pyasn1.codec.der.decoder import decode
    from pyasn1.type import char
    decoded_asn1, _ = decode(bytes.fromhex(excluded_other_name.other_name.value), asn1Spec=char.UTF8String())
    assert str(decoded_asn1) == OTHER_NAME_CONTENT

