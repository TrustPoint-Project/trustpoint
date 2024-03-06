"""Module that creates CLI command strings for onboarding a device."""

class CliCommandBuilder:
    """Builds CLI command strings for onboarding a device."""

    def trustpoint_client_provision(ctx: dict, short_flags: bool = False) -> str:
        """Builds a CLI command string for the trustpoint_client provision command.

        Args:
            ctx (dict):
                The context of the device to provision / the onboarding process.

        Returns (str): The provisioning CLI command.
        """

        cmd = 'python -m trustpoint_client provision'

        def _flag(key: str, short_flag : str = '') -> str:
            val = ctx.get(key,'')
            if not val: return ''

            if short_flags and short_flag:
              return f' -{short_flag} {val}'
            return f' --{key} {val}'
        
        cmd = 'python -m trustpoint_client provision'
        cmd += _flag('tsotp', 'p')
        cmd += _flag('tssalt', 'z')
        cmd += _flag('otp', 'o')
        cmd += _flag('salt', 's')
        cmd += _flag('url', 'u')
        cmd += _flag('host', 'h')
        cmd += _flag('sn', 'n')
        
        return cmd

    def cli_get_trust_store(ctx: dict) -> str:
        """Builds a CLI command string to download the trust store.

        Args:
            ctx (dict):
                The context of the device to provision / the onboarding process.

        Returns (str): The CLI command.
        """
        
        return ('curl -k -X GET https://'
               f'{ctx.get('host','')}/onboarding/api/trust-store/{ctx.get('url','')}/'
               ' -o tp-trust-store.pem -D tp-headers.txt')
        
