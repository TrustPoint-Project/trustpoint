"""Django management commands for the PKI application."""


from enum import Enum


class Algorithm(Enum):
    RSA2048 = 'rsa2048'
    RSA4096 = 'rsa4096'
    SECP256 = 'secp256'
    SECP521 = 'secp521'
