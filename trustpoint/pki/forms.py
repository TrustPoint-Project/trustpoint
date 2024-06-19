from __future__ import annotations

from django import forms


class CertificateDownloadForm(forms.Form):
    cert_file_container = forms.ChoiceField(
        label='Select Certificate Container Type',
        choices=[
            ('single_file', 'Single File'),
            ('zip', 'Separate Certificate Files (as .zip file)'),
            ('tar_gz', 'Separate Certificate Files (as .tar.gz file)')
        ],
        initial='single_file',
        required=True)

    cert_chain_incl = forms.ChoiceField(
        label='Select Included Certificates',
        choices=[
            ('cert_only', 'Selected certificates only'),
            ('chain_incl', 'Include certificate chains')
        ],
        initial='selected_cert_only',
        required=True
    )

    cert_file_format = forms.ChoiceField(
        label='Select Certificate File Format',
        choices=[
            ('pem', 'PEM (.pem, .crt, .ca-bundle)'),
            ('der', 'DER (.der, .cer)'),
            ('pkcs7_pem', 'PKCS#7 (PEM) (.p7b, .p7c, .keystore)'),
            ('pkcs7_der', 'PKCS#7 (DER) (.p7b, .p7c, .keystore)')
        ],
        initial='pem',
        required=True)
