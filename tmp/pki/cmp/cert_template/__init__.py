from pki.pki.cmp.asn1_modules import (
    AttributeTypeAndValue,
    AlgIdCtrl,
    RsaKeyLenCtrl,
    Controls,
    CertReqTemplateContent,
    CertProfileOids
)

import os

from .cert_template_loader import CertTemplateLoader

def load_cert_templates():
    current_directory = os.path.dirname(__file__)
    loader = CertTemplateLoader(current_directory)
    return loader.load_templates()

cert_templates = load_cert_templates()

__all__ = [
    'CertTemplateLoader',
    'cert_templates'
]
