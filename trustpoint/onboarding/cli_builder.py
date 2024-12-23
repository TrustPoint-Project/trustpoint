"""Module that creates CLI command strings for onboarding a device."""

from onboarding.crypto_backend import PBKDF2_DKLEN, PBKDF2_ITERATIONS
from pki.util.keys import SignatureSuite

class CliCommandBuilder:
    """Builds CLI command strings for onboarding a device."""

    @staticmethod
    def trustpoint_client_provision(ctx: dict, *, short_flags: bool = False) -> str:
        """Builds a CLI command string for the trustpoint_client provision command.

        Args:
            ctx (dict):
                The context of the device to provision / the onboarding process.
            short_flags (bool):
                Whether to use short flags for the CLI command.

        Returns (str): The provisioning CLI command.
        """
        def _flag(key: str, short_flag: str = '') -> str:
            val = ctx.get(key,'')
            if not val:
                return ''

            if short_flags and short_flag:
                return f' -{short_flag} {val}'
            return f' --{key} {val}'

        cmd = 'trustpoint-client onboard auto'
        cmd += _flag('otp', 'o')
        cmd += _flag('device', 'd')
        cmd += _flag('host', 'h')


        return cmd

    @staticmethod
    def cli_mkdir_trustpoint() -> str:
        """Builds a CLI command string to create a directory trustpoint for following CLI commands.

        Returns (str): The CLI command.
        """
        return 'mkdir trustpoint && cd trustpoint'

    @staticmethod
    def cli_get_trust_store(ctx: dict) -> str:
        """Builds a CLI command string to download the trust store.

        Args:
            ctx (dict):
                The context of the device to provision / the onboarding process.

        Returns (str): The CLI command.
        """
        return (
            f'curl -k -X GET https://{ctx.get("host", "")}/api/onboarding/trust-store/{ctx.get("url", "")}'
            f' -o tp-trust-store.pem -D tp-headers.txt')

    @staticmethod
    def cli_get_header_hmac() -> str:
        """Builds a CLI command string to get the HTTP header 'hmac-signature' from the trust store response

        Returns (str): The CLI command.
        """
        return "cat tp-headers.txt | grep hmac-signature | tr -d '\\r' | tail -c 65 > tp-resp.hmac"

    @staticmethod
    def cli_get_kdf(ctx: dict) -> str:
        """Builds a CLI command string to derive the key used for the trust store HMAC.

        Args:
            ctx (dict):
                The context of the device to provision / the onboarding process.

        Returns (str): The CLI command.
        """
        return (
            f'openssl kdf -keylen {PBKDF2_DKLEN} \\\n'
            '\t\t\t-kdfopt digest:SHA256 \\\n'
            f'\t\t\t-kdfopt pass:{ctx.get("otp", "")} \\\n'
            f'\t\t\t-kdfopt salt:{ctx.get("device", "")} \\\n'
            f'\t\t\t-kdfopt iter:{PBKDF2_ITERATIONS} \\\n'
            '\t\t\t-binary \\\n'
            '\t\t\t-out tp-key.bin PBKDF2')

    @staticmethod
    def cli_calc_hmac() -> str:
        """Calculates the HMAC of the downloaded trust store with the derived key.

        Returns (str): The CLI command.
        """
        return (
            'cat tp-trust-store.pem | openssl dgst -sha256 -mac hmac -macopt hexkey:$(xxd -p -c 32 tp-key.bin) '
            '| tail -c 65 > tp.hmac')

    @staticmethod
    def cli_compare_hmac() -> str:
        """Compares the HMAC of the trust store with the HMAC from the response header.

        Returns (str): The CLI command.
        """
        return 'if [ "" = "$(diff tp-resp.hmac tp.hmac)" ]; then mv tp-trust-store.pem trust-store.pem; fi && rm tp*'

    @staticmethod
    def cli_gen_key_and_csr(ctx: dict) -> str:
        """Generates a private key and a CSR.

        Returns (str): The CLI command.
        """
        sig_suite = ctx.get('sig_suite', '')

        hash_flag = '-sha256'
        if sig_suite == SignatureSuite.SECP384R1:
            hash_flag = '-sha384'

        key_flag = 'ec -pkeyopt ec_paramgen_curve:prime256v1' # default/fallback to SECP256R1
        if sig_suite == SignatureSuite.SECP384R1:
            key_flag = 'ec -pkeyopt ec_paramgen_curve:secp384r1'
        elif sig_suite == SignatureSuite.RSA4096:
            key_flag = 'rsa:4096'
        elif sig_suite == SignatureSuite.RSA3072:
            key_flag = 'rsa:3072'
        elif sig_suite == SignatureSuite.RSA2048:
            key_flag = 'rsa:2048'
        

        return (
            'openssl  req -nodes -outform PEM -new -out ldevid.csr \\\n'
            '-keyform PEM -keyout ldevid-private-key.pem \\\n'
            f'-subj "/" {hash_flag} -newkey {key_flag}')

    @staticmethod
    def cli_get_ldevid(ctx: dict) -> str:
        """Builds a CLI command string to get the LDevID certificate.

        Args:
            ctx (dict):
                The context of the device to provision / the onboarding process.

        Returns (str): The CLI command.
        """
        return (
            f'curl -X POST https://{ctx.get("host", "")}/api/onboarding/ldevid/{ctx.get("url", "")} \\\n'
            f'--user {ctx.get("device", "")}:{ctx.get("otp", "")} \\\n'
            '-F "ldevid.csr=@ldevid.csr" \\\n'
            '--cacert trust-store.pem > ldevid.pem')

    @staticmethod
    def cli_rm_csr() -> str:
        """Builds a CLI command string to remove the CSR file.

        Returns (str): The CLI command.
        """
        return 'rm ldevid-csr.pem'

    @staticmethod
    def cli_get_cert_chain(ctx: dict) -> str:
        """Builds a CLI command string to get the certificate chain of the LDevID certificate.

        Args:
            ctx (dict):
                The context of the device to provision / the onboarding process.

        Returns (str): The CLI command.
        """
        return (
            f'curl -X GET https://{ctx.get("host", "")}/api/onboarding/ldevid/cert-chain/{ctx.get("url", "")} \\\n'
            '--cert ldevid.pem --key ldevid-private-key.pem \\\n'
            '--cacert trust-store.pem > ldevid-cert-chain.pem')
