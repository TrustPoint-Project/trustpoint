"""Views for the users application."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, ClassVar

from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.management import call_command
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import FormView, TemplateView, View
from pki.models import CertificateChainOrderModel, CertificateModel, CredentialModel
from pki.models.truststore import TrustpointTlsServerCredentialModel

from setup_wizard import SetupWizardState
from setup_wizard.forms import EmptyForm, StartupWizardTlsCertificateForm
from setup_wizard.tls_credential import Generator
from trustpoint.settings import DOCKER_CONTAINER

APACHE_PATH = Path(__file__).parent.parent.parent / 'docker/apache/tls'
APACHE_KEY_PATH = APACHE_PATH / Path('apache-tls-server-key.key')
APACHE_CERT_PATH = APACHE_PATH / Path('apache-tls-server-cert.pem')
APACHE_CERT_CHAIN_PATH = APACHE_PATH / Path('apache-tls-server-cert-chain.pem')

STATE_FILE_DIR = Path('/etc/trustpoint/wizard/transition/')
SCRIPT_WIZARD_INITIAL = STATE_FILE_DIR / Path('wizard_initial.sh')
SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY = STATE_FILE_DIR / Path('wizard_tls_server_credential_apply.sh')
SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY_CANCEL = STATE_FILE_DIR / Path('wizard_tls_server_credential_apply_cancel.sh')
SCRIPT_WIZARD_DEMO_DATA = STATE_FILE_DIR / Path('wizard_demo_data.sh')
SCRIPT_WIZARD_CREATE_SUPER_USER = STATE_FILE_DIR / Path('wizard_create_super_user.sh')


class TrustpointWizardError(Exception):
    """Custom exception for Trustpoint wizard-related issues."""

class TrustpointTlsServerCredentialError(Exception):
    """Custom exception for errors related to Trustpoint TLS Server Credentials.

    This exception is raised when specific issues with the TLS Server Credentials
    occur, such as missing credentials.
    """
    def __init__(self, message: str = 'Trustpoint TLS Server Credential error occurred.') -> None:
        """Initialize the exception with a custom error message.

        Args:
            message (str): A custom error message describing the exception. Defaults
                           to 'Trustpoint TLS Server Credential error occurred.'.
        """
        super().__init__(message)

def execute_shell_script(script_path: str) -> None:
    """Execute a shell script.

    Args:
        script_path (str): The path to the shell script to execute.

    Raises:
        FileNotFoundError: If the script does not exist.
        ValueError: If the script path is not a valid file.
        subprocess.CalledProcessError: If the script fails to execute.
    """
    script_path = Path(script_path).resolve()

    if not script_path.exists():
        err_msg = f'State bump script not found: {script_path}'
        raise FileNotFoundError(err_msg)
    if not script_path.is_file():
        err_msg = f'The script path {script_path} is not a valid file.'
        raise ValueError(err_msg)

    command = ['sudo', str(script_path)]

    result = subprocess.run(  # noqa: S603
        command, capture_output=True, text=True, check=True
    )

    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, str(script_path))



class StartupWizardRedirect:
    """Handles redirection logic based on the current state of the setup wizard.

    This class provides a static method for determining the appropriate redirection
    URL based on the wizard's state, ensuring users are guided through the setup process.
    """
    @staticmethod
    def redirect_by_state(wizard_state: SetupWizardState) -> HttpResponseRedirect:
        """Redirects the user to the appropriate setup wizard page based on the current state.

        Args:
            wizard_state (SetupWizardState): The current state of the setup wizard.

        Returns:
            HttpResponseRedirect: A redirection response to the appropriate page.

        Raises:
            ValueError: If the wizard state is unrecognized or invalid.
        """
        if wizard_state == SetupWizardState.WIZARD_INITIAL:
            return redirect('setup_wizard:initial', permanent=False)
        if wizard_state == SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY:
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)
        if wizard_state == SetupWizardState.WIZARD_DEMO_DATA:
            return redirect('setup_wizard:demo_data', permanent=False)
        if wizard_state == SetupWizardState.WIZARD_CREATE_SUPER_USER:
            return redirect('setup_wizard:create_super_user', permanent=False)
        if wizard_state == SetupWizardState.WIZARD_COMPLETED:
            return redirect('users:login', permanent=False)
        err_msg = 'Unknown wizard state found. Failed to redirect by state.'
        raise ValueError(err_msg)


class SetupWizardInitialView(TemplateView):
    """View for the initial step of the setup wizard.

    This view is responsible for displaying the initial setup wizard page. It
    ensures that the application is running in a Docker container and that the
    setup wizard is in the initial state. If either condition is not met, the
    user is redirected to the appropriate page, such as the login page or the
    next setup step.

    Attributes:
        http_method_names (ClassVar[list[str]]): List of HTTP methods allowed for this view.
        template_name (str): Path to the template used for rendering the initial page.
    """
    http_method_names: ClassVar[list[str]] = ['get']
    template_name = 'setup_wizard/initial.html'

    def get(self, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests for the initial setup wizard page.

        This method validates the current state of the setup wizard and redirects
        the user to the appropriate page. If the application is not running in a
        Docker container, the user is redirected to the login page.

        Args:
            *args (Any): Additional positional arguments.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            HttpResponse: A redirect response to the appropriate setup wizard page
                          or the login page if the setup is not in a Docker container.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_INITIAL:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().get(*args, **kwargs)


class SetupWizardGenerateTlsServerCredentialView(FormView):
    """View for generating TLS Server Credentials in the setup wizard.

    This view handles the generation of TLS Server Credentials as part of the
    setup wizard. It provides a form for the user to input necessary information
    such as IP addresses and domain names, and processes the data to generate
    the required TLS certificates.

    Attributes:
        http_method_names (ClassVar[list[str]]): HTTP methods allowed for this view.
        template_name (str): Path to the template used for rendering the form.
        form_class (Form): The form class used to validate user input.
        success_url (str): The URL to redirect to upon successful credential generation.
    """
    http_method_names: ClassVar[list[str]] = ['get', 'post']
    template_name = 'setup_wizard/generate_tls_server_credential.html'
    form_class = StartupWizardTlsCertificateForm
    success_url = reverse_lazy('setup_wizard:tls_server_credential_apply')

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Override the dispatch method to enforce wizard state validation.

        This method ensures that the user is redirected appropriately based on the
        current wizard state. If the application is not running in a Docker container,
        the user is redirected to the login page.

        Args:
            request (HttpRequest): The incoming HTTP request.
            *args (Any): Additional positional arguments.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            HttpResponse: A redirect response to the appropriate page or
                          the next handler in the dispatch chain.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_INITIAL:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: UserCreationForm) -> HttpResponseRedirect:
        """Handle a valid form submission for TLS Server Credential generation.

        Args:
            form (UserCreationForm): The validated form containing user input
                                     for generating the TLS Server Credential.

        Returns:
            HttpResponseRedirect: Redirect to the success URL upon successful
                                  credential generation, or an error page if
                                  an exception occurs.

        Raises:
            TrustpointTlsServerCredentialError: If no TLS server credential is found.
            subprocess.CalledProcessError: If the associated shell script fails.
        """
        try:
            # Generate the TLS Server Credential
            cleaned_data = form.cleaned_data
            generator = Generator(
                ipv4_addresses=cleaned_data['ipv4_addresses'],
                ipv6_addresses=cleaned_data['ipv6_addresses'],
                domain_names=cleaned_data['domain_names'],
            )
            tls_server_credential = generator.generate_tls_credential()

            # Save the main certificate
            credential_certificate = tls_server_credential.credential_certificate.as_crypto()
            certificate_model = CertificateModel.save_certificate(credential_certificate)

            # Save the private key
            private_key_pem = tls_server_credential.credential_private_key.as_pkcs8_pem().decode()

            # Save the credential and chain
            credential_model = CredentialModel.objects.create(
                credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
                certificate=certificate_model,
                private_key=private_key_pem,
            )

            # Save the certificate chain
            for order, additional_certificate in enumerate(tls_server_credential.additional_certificates.as_crypto()):
                chain_certificate_model = CertificateModel.save_certificate(additional_certificate)
                CertificateChainOrderModel.objects.create(
                    credential=credential_model, certificate=chain_certificate_model, order=order
                )

            execute_shell_script(SCRIPT_WIZARD_INITIAL)

            messages.add_message(self.request, messages.SUCCESS, 'TLS Server Credential generated successfully.')

            return super().form_valid(form)
        except subprocess.CalledProcessError as e:
            error_message = self._get_error_message_from_return_code(e.returncode)
            messages.add_message(self.request, messages.ERROR, f'Script error: {error_message}')
            return redirect('setup_wizard:initial', permanent=False)
        except FileNotFoundError:
            messages.add_message(self.request, messages.ERROR, f'Transition script not found: {SCRIPT_WIZARD_INITIAL}.')
            return redirect('setup_wizard:initial', permanent=False)
        except Exception as e: # noqa: BLE001
            messages.add_message(self.request, messages.ERROR, f'Error generating TLS Server Credential: {e}')
            return redirect('setup_wizard:initial', permanent=False)

    def _get_error_message_from_return_code(self, return_code: int) -> str:
        """Maps return codes to error messages."""
        error_messages = {
            1: 'Trustpoint is not in the WIZARD_INITIAL state. State file missing.',
            2: 'Multiple state files detected. Wizard state is corrupted.',
            3: 'Failed to remove the WIZARD_INITIAL state file.',
            4: 'Failed to create the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file.',
        }
        return error_messages.get(return_code, 'An unknown error occurred.')


class SetupWizardImportTlsServerCredentialView(View):
    """View for handling the import of TLS Server Credentials."""
    http_method_names: ClassVar[list[str]] = ['get']

    def get(self) -> HttpResponse:
        """Handle GET requests for importing TLS Server Credentials.

        Returns:
            HttpResponse: A redirect to the initial setup wizard page if the
                          import feature is not implemented or the wizard state
                          is incorrect.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_INITIAL:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        messages.add_message(
            self.request, messages.ERROR, 'Import of the TLS-Server credential is not yet implemented.'
        )
        return redirect('setup_wizard:initial', permanent=False)


class SetupWizardTlsServerCredentialApplyView(FormView):
    """View for handling the application of TLS Server Credentials in the setup wizard.

    Attributes:
        http_method_names (list[str]): Allowed HTTP methods for this view ('get' and 'post').
        form_class (Form): The form used for processing TLS Server Credential application.
        template_name (str): The template used to render the view.
        success_url (str): The URL to redirect to upon successful form submission.
    """
    http_method_names: ClassVar[list[str]] = ['get', 'post']
    form_class = EmptyForm
    template_name = 'setup_wizard/tls_server_credential_apply.html'
    success_url = reverse_lazy('setup_wizard:demo_data')

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests for the TLS Server Credential application view.

        Args:
            request (HttpRequest): The HTTP request object.
            *args (Any): Positional arguments passed to the method.
            **kwargs (Any): Keyword arguments passed to the method.

        Returns:
            HttpResponse: A redirect response to the appropriate wizard state or the requested page.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        file_format = self.kwargs.get('file_format')
        if file_format:
            return self._generate_trust_store_response(file_format)

        return super().get(request, *args, **kwargs)

    def post(self, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle POST requests for the TLS Server Credential application view.

        Args:
            *args (Any): Positional arguments passed to the method.
            **kwargs (Any): Keyword arguments passed to the method.

        Returns:
            HttpResponse: A redirect response to the appropriate page based on the wizard state.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().post(*args, **kwargs)

    def form_valid(self, form: UserCreationForm) -> HttpResponseRedirect:
        """Process a valid form submission during the TLS Server Credential application.

        Args:
            form (UserCreationForm): The form instance containing the submitted data.

        Returns:
            HttpResponseRedirect: Redirect to the next step or an error page based on the outcome.
        """
        try:
            trustpoint_tls_server_credential_model = CredentialModel.objects.get(
                credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
            )
            if not trustpoint_tls_server_credential_model:
                self._raise_tls_credential_error('No Trustpoint TLS Server Credential found.')

            self._write_pem_files(trustpoint_tls_server_credential_model)

            execute_shell_script(SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY)

            messages.add_message(self.request, messages.SUCCESS, 'TLS Server Credential applied successfully.')
            return super().form_valid(form)

        except subprocess.CalledProcessError as e:
            error_message = self._map_exit_code_to_message(e.returncode)
            messages.add_message(self.request, messages.ERROR, f'Error applying TLS Server Credential: {error_message}')
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)
        except FileNotFoundError as e:
            messages.add_message(self.request, messages.ERROR, f'File not found: {e}')
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        except TrustpointWizardError as e:
            messages.add_message(self.request, messages.ERROR, str(e))
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)
        except Exception as e:  #noqa: BLE001
            messages.add_message(self.request, messages.ERROR, f'An unexpected error occurred: {e}')
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

    def _raise_tls_credential_error(self, message: str) -> None:
        """Raise a TrustpointTlsServerCredentialError with a given message.

        Args:
            message (str): The error message to include in the exception.
        """
        raise TrustpointTlsServerCredentialError(message)

    def _map_exit_code_to_message(self, return_code: int) -> str:
        """Maps shell script exit codes to user-friendly error messages."""
        error_messages = {
            1: 'State file not found. Ensure Trustpoint is in the correct state.',
            2: 'Multiple state files detected. The wizard state is corrupted.',
            3: 'Failed to create the required TLS directory for Apache.',
            4: 'Failed to clear existing files in the Apache TLS directory.',
            5: 'Failed to copy Trustpoint TLS files to the Apache directory.',
            6: 'Failed to remove existing Apache sites from sites-enabled.',
            7: 'Failed to copy HTTP config to Apache sites-available.',
            8: 'Failed to copy HTTP config to Apache sites-enabled.',
            9: 'Failed to copy HTTPS config to Apache sites-available.',
            10: 'Failed to copy HTTPS config to Apache sites-enabled.',
            11: 'Failed to enable Apache mod_ssl.',
            12: 'Failed to enable Apache mod_rewrite.',
            13: 'Failed to restart Apache gracefully.',
            14: 'Failed to remove the current state file.',
            15: 'Failed to create the next state file.',
        }
        return error_messages.get(return_code, 'An unknown error occurred.')

    def _generate_trust_store_response(self, file_format: str) -> HttpResponse:
        """Generate a response containing the trust store in the requested format.

        Args:
            file_format (str): The desired file format for the trust store (e.g., 'pem', 'pkcs7_der', 'pkcs7_pem').

        Returns:
            HttpResponse: A response with the trust store content or an error message.
        """
        try:
            trustpoint_tls_server_credential_model = CredentialModel.objects.get(
                credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
            )
        except CredentialModel.DoesNotExist:
            messages.add_message(self.request, messages.ERROR, 'No trust store available for download.')
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        valid_formats = {'pem', 'pkcs7_der', 'pkcs7_pem'}
        if file_format not in valid_formats:
            messages.add_message(
                self.request,
                messages.ERROR,
                f"Invalid file format requested: {file_format}. Supported formats: {', '.join(valid_formats)}.",
            )
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        try:
            serializer = trustpoint_tls_server_credential_model.certificate.get_certificate_serializer()
            if file_format == 'pem':
                trust_store = serializer.as_pem().decode()
                content_type = 'application/x-pem-file'
            elif file_format == 'pkcs7_der':
                trust_store = serializer.as_pkcs7_der()
                content_type = 'application/pkcs7-mime'
            elif file_format == 'pkcs7_pem':
                trust_store = serializer.as_pkcs7_pem().decode()
                content_type = 'application/x-pem-file'
        except Exception as e:  # noqa: BLE001
            messages.add_message(self.request, messages.ERROR, f'Error generating {file_format} trust store: {e}')
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        response = HttpResponse(content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="trust_store.{file_format}"'
        response.write(trust_store)
        return response

    def _write_pem_files(self, credential_model: CredentialModel) -> None:
        """Writes the private key, certificate, and trust store PEM files to disk.

        Args:
            credential_model (CredentialModel): The credential model instance containing the keys and certificates.
        """
        private_key_pem = credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
        certificate_pem = credential_model.get_certificate_serializer().as_pem().decode()
        trust_store_pem = credential_model.get_certificate_chain_serializer().as_pem().decode()

        APACHE_KEY_PATH.write_text(private_key_pem)
        APACHE_CERT_PATH.write_text(certificate_pem)
        APACHE_CERT_CHAIN_PATH.write_text(trust_store_pem)


class SetupWizardTlsServerCredentialApplyCancelView(View):
    """View for handling the cancellation of TLS Server Credential application.

    Attributes:
        http_method_names (list[str]): Allowed HTTP methods for this view.
    """
    http_method_names: ClassVar[list[str]] = ['get']

    def get(self, request: HttpRequest) -> HttpResponse:
        """Handle GET requests for the TLS Server Credential import view.

        Args:
            request (HttpRequest): The HTTP request object.

        Returns:
            HttpResponse: A redirect to the next step or an error response.
        """
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        try:
            self._clear_credential_and_certificate_data()

            execute_shell_script(SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY_CANCEL)

            messages.add_message(request, messages.INFO, 'Generation of the TLS-Server credential canceled.')
            return redirect('setup_wizard:initial', permanent=False)

        except subprocess.CalledProcessError as e:
            messages.add_message(
                request,
                messages.ERROR,
                f'Cancel script failed with exit code {e.returncode}: {self._map_exit_code_to_message(e.returncode)}',
            )
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        except FileNotFoundError:
            messages.add_message(
                request, messages.ERROR, f'Cancel script not found: {SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY_CANCEL}'
            )
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

        except Exception as e:  # noqa: BLE001
            messages.add_message(request, messages.ERROR, f'An unexpected error occurred: {e}')
            return redirect('setup_wizard:tls_server_credential_apply', permanent=False)

    def _clear_credential_and_certificate_data(self) -> None:
        """Clears credential and certificate data."""
        CertificateModel.objects.all().delete()
        TrustpointTlsServerCredentialModel.objects.all().delete()

    def _map_exit_code_to_message(self, return_code:int) -> str:
        """Maps shell script exit codes to user-friendly error messages."""
        error_messages = {
            1: "The state file for 'WIZARD_TLS_SERVER_CREDENTIAL_APPLY' was not found. Ensure Trustpoint "
               "is in the correct state.",
            2: 'Multiple state files were detected, indicating a corrupted wizard state. '
               'Please resolve the inconsistency.',
            3: "Failed to remove the current 'WIZARD_TLS_SERVER_CREDENTIAL_APPLY' state file. Check file permissions.",
            4: "Failed to create the 'WIZARD_INITIAL' state file. Ensure the directory is writable and "
               "permissions are set correctly.",
        }
        return error_messages.get(return_code, 'An unknown error occurred during the cancel operation.')


class SetupWizardDemoDataView(FormView):
    """View for handling the demo data setup during the setup wizard.

    This view allows the user to either add demo data to the database or proceed without
    it. It validates the current wizard state and transitions to the next state upon
    successful completion.
    """
    http_method_names: ClassVar[list[str]] = ['get', 'post']
    form_class = EmptyForm
    template_name = 'setup_wizard/demo_data.html'
    success_url = reverse_lazy('setup_wizard:create_super_user')

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle request dispatch and wizard state validation."""
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_DEMO_DATA:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: UserCreationForm) -> HttpResponseRedirect:
        """Handle form submission for demo data setup."""
        try:
            if 'without-demo-data' in self.request.POST:
                self._execute_state_bump()
            elif 'with-demo-data' in self.request.POST:
                self._add_demo_data()
                execute_shell_script(SCRIPT_WIZARD_DEMO_DATA)
            else:
                messages.add_message(self.request, messages.ERROR, 'Invalid option selected for demo data setup.')
                return redirect('setup_wizard:demo_data', permanent=False)

        except subprocess.CalledProcessError as e:
            messages.add_message(
                self.request,
                messages.ERROR,
                f'Demo data script failed with exit code {e.returncode}: '
                f'{self._map_exit_code_to_message(e.returncode)}',
            )
            return redirect('setup_wizard:demo_data', permanent=False)
        except FileNotFoundError:
            messages.add_message(self.request, messages.ERROR, f'Demo data script not found: {SCRIPT_WIZARD_DEMO_DATA}')
            return redirect('setup_wizard:demo_data', permanent=False)
        except ValueError as e:
            messages.add_message(self.request, messages.ERROR, f'Value error: {e}')
            return redirect('setup_wizard:demo_data', permanent=False)
        except Exception as e:  # noqa: BLE001
            messages.add_message(self.request, messages.ERROR, f'An unexpected error occurred: {e}')
            return redirect('setup_wizard:demo_data', permanent=False)

        return super().form_valid(form)

    def _add_demo_data(self) -> None:
        """Add demo data to the database."""
        try:
            call_command('add_domains_and_devices')
        except Exception as e:
            err_msg = f'Error adding demo data: {e}'
            raise ValueError(err_msg) from e

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages.

        Args:
            return_code (int): The exit code returned by the script.

        Returns:
            str: A descriptive error message corresponding to the exit code.
        """
        error_messages = {
            1: 'Trustpoint is not in the WIZARD_DEMO_DATA state.',
            2: 'Found multiple wizard state files. The wizard state seems to be corrupted.',
            3: 'Failed to remove the WIZARD_DEMO_DATA state file.',
            4: 'Failed to create WIZARD_CREATE_SUPER_USER state file.',
        }
        return error_messages.get(return_code, 'An unknown error occurred while executing the demo data script.')


class SetupWizardCreateSuperUserView(FormView):
    """View for handling the creation of a superuser during the setup wizard.

    This view is part of the setup wizard process. It allows an admin to create a
    superuser account, ensuring that the application has at least one administrative
    user configured. The view validates the input using the `UserCreationForm`
    and transitions the wizard state upon successful completion.
    """
    http_method_names: ClassVar[list[str]] = ['get', 'post']
    form_class = UserCreationForm
    template_name = 'setup_wizard/create_super_user.html'
    success_url = reverse_lazy('users:login')

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle request dispatch and wizard state validation."""
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_CREATE_SUPER_USER:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: UserCreationForm) -> HttpResponseRedirect:
        """Handle form submission for creating a superuser.

        Args:
            form (UserCreationForm): The form containing the data for the superuser creation.

        Returns:
            HttpResponseRedirect: Redirect to the next step or login page.
        """
        try:
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            call_command('createsuperuser', interactive=False, username=username, email='')

            user = User.objects.get(username=username)
            user.set_password(password)
            user.save()
            messages.add_message(self.request, messages.SUCCESS, 'Successfully created super-user.')

            execute_shell_script(SCRIPT_WIZARD_CREATE_SUPER_USER)
        except User.DoesNotExist as e:
            messages.add_message(self.request, messages.ERROR, f'User not found error: {e}')
            return redirect('setup_wizard:create_super_user', permanent=False)
        except subprocess.CalledProcessError as e:
            messages.add_message(
                self.request,
                messages.ERROR,
                f'Create superuser script failed with exit code {e.returncode}: '
                f'{self._map_exit_code_to_message(e.returncode)}',
            )
            return redirect('setup_wizard:create_super_user', permanent=False)
        except FileNotFoundError:
            messages.add_message(
                self.request, messages.ERROR, f'Create superuser script not found: {SCRIPT_WIZARD_CREATE_SUPER_USER}'
            )
            return redirect('setup_wizard:create_super_user', permanent=False)
        except ValueError as e:
            messages.add_message(self.request, messages.ERROR, f'Value error occurred: {e}')
            return redirect('setup_wizard:create_super_user', permanent=False)
        except Exception as e:  # noqa: BLE001
            messages.add_message(self.request, messages.ERROR, f'An unexpected error occurred: {e}')
            return redirect('setup_wizard:create_super_user', permanent=False)

        return super().form_valid(form)

    @staticmethod
    def _map_exit_code_to_message(return_code: int) -> str:
        """Map script exit codes to meaningful error messages."""
        error_messages = {
            1: 'Trustpoint is not in the WIZARD_CREATE_SUPER_USER state.',
            2: 'Found multiple wizard state files. The wizard state seems to be corrupted.',
            3: 'Failed to remove the WIZARD_CREATE_SUPER_USER state file.',
            4: 'Failed to create the WIZARD_COMPLETED state file.',
        }
        return error_messages.get(return_code, 'An unknown error occurred while executing the create superuser script.')
