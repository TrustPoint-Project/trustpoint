import requests
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7


tests_data_path = Path(__file__).parent.parent / Path('data/issuing_ca')


def load_request() -> bytes:
    with open(tests_data_path / Path('csr0.pem'), 'rb') as f:
        return f.read()


def request_certificate(csr_: bytes):
    response = requests.post(
        'http://localhost:8000/.well-known/est/issuing-ca/simpleenroll/',
        data=csr_,
        headers={'Content-Type': 'application/pkcs10 '})
    return response


if __name__ == '__main__':
    csr = load_request()
    loaded_csr = x509.load_pem_x509_csr(csr)
    # for extension in loaded_csr.extensions:
    #     print(extension)
    #     print(extension.critical)

    resp = request_certificate(csr)
    r = pkcs7.load_der_pkcs7_certificates(resp.content)
    print(r)
