from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cert_path_validator import PathValidator


def load_certificate_chain(pem_file_path):
    with open(pem_file_path, 'rb') as pem_file:
        pem_data = pem_file.read()

    certificates = pem_data.split(b'-----END CERTIFICATE-----\n')

    cert_list = []
    for cert_data in certificates:
        if cert_data.strip():
            cert = x509.load_pem_x509_certificate(cert_data + b'-----END CERTIFICATE-----\n', default_backend())
            cert_list.append(cert)

    return cert_list

cert_chain = load_certificate_chain('OiPKIsubTlsCertCA-chain(2).pem')

root_cert = cert_chain[0]

user_initial_policy_set = {"2.5.29.32.0"}
initial_policy_mapping_inhibit = False
initial_explicit_policy = True
initial_any_policy_inhibit = False
initial_permitted_subtrees = {"C": ["DE"]}
initial_excluded_subtrees = {"DNS": ["excluded.example.com"]}

path_validator = PathValidator(
    trust_anchor=root_cert,
    user_initial_policy_set=user_initial_policy_set,
    initial_policy_mapping_inhibit=initial_policy_mapping_inhibit,
    initial_explicit_policy=initial_explicit_policy,
    initial_any_policy_inhibit=initial_any_policy_inhibit,
    initial_permitted_subtrees=initial_permitted_subtrees,
    initial_excluded_subtrees=initial_excluded_subtrees,
)
result = path_validator.validate(cert_chain)

print(result)


