from .cert_template_loader import CertTemplateLoader
import os

def load_cert_templates():
    current_directory = os.path.dirname(__file__)
    loader = CertTemplateLoader(current_directory)
    return loader.load_templates()

cert_templates = load_cert_templates()

__all__ = ['CertTemplateLoader', 'cert_templates']
