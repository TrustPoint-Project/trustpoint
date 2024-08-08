import requests
from pathlib import Path


tests_data_path = Path(__file__).parent.parent / Path('data/issuing_ca')


def load_request() -> bytes:
    with open(tests_data_path / Path('csr0.pem'), 'rb') as f:
        return f.read()


def request_certificate(csr_: bytes) -> None:
    response = requests.post(
        'http://localhost:8000/.well-known/est/issuing-ca/simpleenroll/',
        data=csr_,
        headers={'Content-Type': 'application/pkcs10 '})
    print(response)


if __name__ == '__main__':
    csr = load_request()
    request_certificate(csr)
