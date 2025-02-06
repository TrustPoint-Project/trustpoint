import importlib

modules_to_import = [
    'pki.pki.cmp.asn1_modules',
    'pki.pki.cmp.cert_template',
    'pki.pki.cmp.builder',
    'pki.pki.cmp.protection',
    'pki.pki.cmp.parsing',
    'pki.pki.cmp.validator',
    'pki.pki.cmp.messagehandler',
    'pki.pki.cmp.errorhandling'
]

def test_imports(modules):
    for module_name in modules:
        try:
            # Attempt to import the module
            module = importlib.import_module(module_name)
            print(f"Successfully imported {module_name}")
        except ImportError as e:
            print(f"Failed to import {module_name}: {str(e)}")
        except Exception as e:
            print(f"An error occurred while importing {module_name}: {str(e)}")

if __name__ == "__main__":
    test_imports(modules_to_import)