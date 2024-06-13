from django.contrib import admin


from .models import (
    Certificate,
    BasicConstraintsExtension,
    KeyUsageExtension,
    AttributeTypeAndValue,
    IssuerAlternativeNameExtension,
    SubjectAlternativeNameExtension,
    TrustStore)


class TrustStoreAdmin(admin.ModelAdmin):
    readonly_fields = [
        'unique_name',
        'leaf_certs'
    ]


class AttributeTypeAndValueAdmin(admin.ModelAdmin):
    readonly_fields = (
        'oid',
        'value'
    )


class AlternativeNameExtensionAdmin(admin.ModelAdmin):
    readonly_fields = (
        'extension_oid',
        'critical',
        'rfc822_names',
        'dns_names',
        'directory_names',
        'uniform_resource_identifiers',
        'ip_addresses',
        'registered_ids',
        'other_names'
    )


class BasicConstraintsExtensionAdmin(admin.ModelAdmin):
    readonly_fields = (
        'extension_oid',
        'critical',
        'ca',
        'path_length_constraint'
    )


class KeyUsageExtensionAdmin(admin.ModelAdmin):
    readonly_fields = (
        'extension_oid',
        'critical',
        'digital_signature',
        'content_commitment',
        'key_encipherment',
        'data_encipherment',
        'key_agreement',
        'key_cert_sign',
        'crl_sign',
        'encipher_only',
        'decipher_only'
    )


class CertificateAdmin(admin.ModelAdmin):
    readonly_fields = (
        'certificate_hierarchy_type',
        'certificate_hierarchy_depth',

        'common_name',
        'sha256_fingerprint',

        'signature_algorithm_oid',
        'signature_algorithm',
        'signature_algorithm_padding_scheme',
        'signature_value',

        'version',
        'serial_number',

        'issuer_public_bytes',
        'issuer',

        'not_valid_before',
        'not_valid_after',

        'subject_public_bytes',
        'subject',

        'spki_algorithm_oid',
        'spki_algorithm',
        'spki_key_size',
        'spki_ec_curve_oid',
        'spki_ec_curve',

        'cert_pem',
        'public_key_pem',
        'private_key_pem',

        'key_usage_extension',
        'subject_alternative_name_extension',
        'issuer_alternative_name_extension',
        'basic_constraints_extension'
    )


admin.site.register(TrustStore, TrustStoreAdmin)
admin.site.register(SubjectAlternativeNameExtension, AlternativeNameExtensionAdmin)
admin.site.register(IssuerAlternativeNameExtension, AlternativeNameExtensionAdmin)
admin.site.register(AttributeTypeAndValue, AttributeTypeAndValueAdmin)
admin.site.register(BasicConstraintsExtension, BasicConstraintsExtensionAdmin)
admin.site.register(KeyUsageExtension, KeyUsageExtensionAdmin)
admin.site.register(Certificate, CertificateAdmin)
