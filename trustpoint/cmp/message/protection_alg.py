from __future__ import annotations

from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2459, rfc4210

from cmp.message.oid import ProtectionAlgorithmOid, HashAlgorithmOid, MacOid


class ProtectionAlgorithmParser:

    @staticmethod
    def parse_protection_algorithm(protection_algorithm: rfc2459.AlgorithmIdentifier) -> None | ProtectionAlgorithm:
        if not protection_algorithm.isValue:
            return None

        if not protection_algorithm['algorithm'].isValue:
            raise ValueError('Algorithm is missing in AlgorithmIdentifier.')

        try:
            protection_algorithm_oid = ProtectionAlgorithmOid(str(protection_algorithm['algorithm']))
        except Exception as exception:
            err_msg = f'Found an unknown protection algorithm: {str(protection_algorithm["algorithm"])}'
            raise ValueError(err_msg)

        if protection_algorithm_oid == ProtectionAlgorithmOid.PASSWORD_BASED_MAC:
            if not protection_algorithm['parameters'].isValue:
                err_msg = 'Found PasswordBasedMacProtection, but parameters are missing.'
                raise ValueError(err_msg)

            try:
                encoded_parameters = encoder.encode(protection_algorithm['parameters'])
                decoded_parameters, _ = decoder.decode(encoded_parameters, asn1Spec=rfc4210.PBMParameter())
            except Exception as exception:
                err_msg = 'Found PasswordBasedMacProtection, but parameters are corrupted.'
                raise ValueError(err_msg)
            return PasswordBasedMacProtection(decoded_parameters)

class ProtectionAlgorithm:

    _oid: ProtectionAlgorithmOid

    def __init__(self, oid: ProtectionAlgorithmOid):
        self._oid = oid

    @property
    def oid(self) -> ProtectionAlgorithmOid:
        return self._oid

class PasswordBasedMacProtection(ProtectionAlgorithm):

    def __init__(self, parameters: rfc4210.PBMParameter) -> None:
        super().__init__(ProtectionAlgorithmOid.PASSWORD_BASED_MAC)

        if not parameters['salt'].isValue:
            err_msg = 'Found PasswordBasedMacProtection, but salt is missing.'
            raise ValueError(err_msg)

        self._salt = parameters['salt'].asOctets()

        if not parameters['owf'].isValue or not parameters['owf']['algorithm']:
            err_msg = 'Found PasswordBasedMacProtection, but owf is missing.'
            raise ValueError(err_msg)

        try:
            self._owf = HashAlgorithmOid(str(parameters['owf']['algorithm']))
        except Exception as exception:
            err_msg = (
                'Found PasswordBasedMacProtection, but contains unknown hash algorithm: '
                f'{str(parameters["owf"]["algorithm"])}.')
            raise ValueError(err_msg) from exception

        if not parameters['iterationCount'].isValue:
            err_msg = 'Found PasswordBasedMacProtection, but iterationCount is missing.'
            raise ValueError(err_msg)

        self._iteration_count = int(parameters['iterationCount'])

        if not parameters['mac'].isValue or not parameters['mac']['algorithm']:
            err_msg = 'Found PasswordBasedMacProtection, but mac is missing.'
            raise ValueError(err_msg)

        try:
            self._mac = MacOid(str(parameters['mac']['algorithm']))
        except Exception as exception:
            err_msg = (
                'Found PasswordBasedMacProtection, but contains unknown mac algorithm: '
                f'{str(parameters["mac"]["algorithm"])}.')
            raise ValueError(err_msg) from exception

    _salt: bytes
    _owf: HashAlgorithmOid
    _iteration_count: int
    _mac: MacOid

    @property
    def salt(self) -> bytes:
        return self._salt

    @property
    def owf(self) -> HashAlgorithmOid:
        return self._owf

    @property
    def iteration_count(self) -> int:
        return self._iteration_count

    @property
    def mac(self) -> MacOid:
        return self._mac

    def __str__(self) -> str:
        return f"""PasswordBasedMacProtection
    Salt:                       {self.salt.hex()}
    OWF:                        {self.owf.name}
    IterationCount:             {self.iteration_count}
    MAC:                        {self.mac.name}"""

    def pretty_print(self) -> None:
        print(str(self))
