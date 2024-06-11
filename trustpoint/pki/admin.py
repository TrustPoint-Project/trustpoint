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
        'version',
        'serial_number',
        'sha256_fingerprint',
        'subject',
        'subject_public_bytes',
        # 'subject',
        # 'issuer',
        'issuer_ref',
        'not_valid_before',
        'not_valid_after',
        'public_key_algorithm_oid',
        'public_key_algorithm',
        'public_key_size',
        'public_key_ec_curve_oid',
        'public_key_ec_curve',
        'signature_algorithm_oid',
        'signature_algorithm',
        'signature_padding_scheme',
        'signature_value',
        'public_key_pem',
        'private_key_pem',
        'cert_pem',
        'public_key_der',
        'cert_der',
        'basic_constraints_extension',
        'key_usage_extension',
        'issuer_alternative_name_extension',
        'subject_alternative_name_extension'
    )


admin.site.register(TrustStore, TrustStoreAdmin)
admin.site.register(SubjectAlternativeNameExtension, AlternativeNameExtensionAdmin)
admin.site.register(IssuerAlternativeNameExtension, AlternativeNameExtensionAdmin)
admin.site.register(AttributeTypeAndValue, AttributeTypeAndValueAdmin)
admin.site.register(BasicConstraintsExtension, BasicConstraintsExtensionAdmin)
admin.site.register(KeyUsageExtension, KeyUsageExtensionAdmin)
admin.site.register(Certificate, CertificateAdmin)
