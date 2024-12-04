"""Views for the users application."""
from __future__ import annotations

from pathlib import Path
import subprocess
from django.contrib import messages

from django.http import HttpResponseRedirect
from django.core.management import call_command
from django.shortcuts import redirect
from django.views.generic import TemplateView, FormView, View
from django.urls import reverse_lazy

from setup_wizard.forms import EmptyForm ,StartupWizardTlsCertificateForm
from setup_wizard.tls_credential import Generator
from setup_wizard import SetupWizardState

from pki.models import CertificateModel
from pki.models.truststore import TrustpointTlsServerCredentialModel, ActiveTrustpointTlsServerCredentialModel

from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

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


class StartupWizardRedirect:

    @staticmethod
    def redirect_by_state(wizard_state: SetupWizardState) -> HttpResponseRedirect:
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
        raise ValueError('Unknown wizard state found. Failed to redirect by state.')


class SetupWizardInitialView(TemplateView):
    http_method_names = ['get']
    template_name = 'setup_wizard/initial.html'

    def get(self, *args, **kwargs):
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_INITIAL:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().get(*args, **kwargs)


class SetupWizardGenerateTlsServerCredentialView(FormView):
    http_method_names = ['get', 'post']
    template_name = 'setup_wizard/generate_tls_server_credential.html'
    form_class = StartupWizardTlsCertificateForm
    success_url = reverse_lazy('setup_wizard:tls_server_credential_apply')

    def get(self, *args, **kwargs):
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_INITIAL:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().get(*args, **kwargs)

    def post(self, *args, **kwargs):
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_INITIAL:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().post(*args, **kwargs)

    def form_valid(self, form):
        cleaned_data = form.cleaned_data
        generator = Generator(
            ipv4_addresses=cleaned_data['ipv4_addresses'],
            ipv6_addresses=cleaned_data['ipv6_addresses'],
            domain_names=cleaned_data['domain_names']
        )
        tls_server_credential = generator.generate_tls_credential()

        trust_store_initializer = TrustStoreInitializer(
            unique_name='Trustpoint-TLS-Server-Credential',
            trust_store=tls_server_credential.additional_certificates.as_pem()
        )
        trust_store_model = trust_store_initializer.save()
        certificate = CertificateModel.save_certificate(certificate=tls_server_credential.credential_certificate.as_crypto())

        trust_store_tls_server_credential_model = TrustpointTlsServerCredentialModel(
            private_key_pem = tls_server_credential.credential_private_key.as_pkcs8_pem().decode(),
            certificate = certificate,
            trust_store = trust_store_model
        )
        trust_store_tls_server_credential_model.save()

        if not SCRIPT_WIZARD_INITIAL.exists():
            raise ValueError(str(SCRIPT_WIZARD_INITIAL))

        # TODO(AlexHx8472): Exception Handling
        proc = subprocess.run(['sudo', f'{SCRIPT_WIZARD_INITIAL}'])

        # TODO(AlexHx8472): Exception Handling
        match proc.returncode:
            case 1:
                raise ValueError('Initial failed with 1')
            case 2:
                raise ValueError('Initial failed with 2')
            case 3:
                raise ValueError('Initial failed with 3')
            case 4:
                raise ValueError('Initial failed with 4')

        return super().form_valid(form)


class SetupWizardImportTlsServerCredentialView(View):
    http_method_names = ['get']

    def get(self, *args, **kwargs):
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_INITIAL:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        messages.add_message(
            self.request,
            messages.ERROR,
            'Import of the TLS-Server credential is not yet implemented.')
        return redirect('setup_wizard:initial', permanent=False)


class SetupWizardTlsServerCredentialApplyView(FormView):
    http_method_names = ['get', 'post']
    form_class = EmptyForm
    template_name = 'setup_wizard/tls_server_credential_apply.html'
    success_url = reverse_lazy('setup_wizard:demo_data')

    def get(self, *args, **kwargs):
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        file_format = self.kwargs.get('file_format')
        if file_format is None:
            return super().get(*args, **kwargs)

        trust_store = TrustpointTlsServerCredentialModel.objects.all()[0].trust_store
        if trust_store is None:
            return super().get(*args, **kwargs)

        return TrustStoreDownloadResponseBuilder(trust_store.id, file_format).as_django_http_response()

    def post(self, *args, **kwargs):
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().post(*args, **kwargs)

    def form_valid(self, form):

        trustpoint_tls_server_credential_model = TrustpointTlsServerCredentialModel.objects.all()[0]
        ActiveTrustpointTlsServerCredentialModel(credential=trustpoint_tls_server_credential_model).save()

        private_key_pem = trustpoint_tls_server_credential_model.private_key_pem
        certificate = trustpoint_tls_server_credential_model.certificate.get_certificate_serializer().as_pem().decode()
        trust_store = trustpoint_tls_server_credential_model.trust_store.get_serializer().as_pem().decode()

        APACHE_KEY_PATH.write_text(private_key_pem)
        APACHE_CERT_PATH.write_text(certificate)
        APACHE_CERT_CHAIN_PATH.write_text(trust_store)

        if not SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY.exists():
            raise ValueError(str(SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY))

        # TODO(AlexHx8472): Exception Handling
        proc = subprocess.run(['sudo', f'{SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY}'])

        # TODO(AlexHx8472): Exception Handling
        match proc.returncode:
            case 1:
                raise ValueError('Credential apply failed with 1')
            case 2:
                raise ValueError('Credential apply failed with 2')
            case 3:
                raise ValueError('Credential apply failed with 3')
            case 4:
                raise ValueError('Credential apply failed with 4')
            case 5:
                raise ValueError('Credential apply failed with 5')
            case 6:
                raise ValueError('Credential apply failed with 6')
            case 7:
                raise ValueError('Credential apply failed with 7')
            case 8:
                raise ValueError('Credential apply failed with 8')
            case 9:
                raise ValueError('Credential apply failed with 9')
            case 10:
                raise ValueError('Credential apply failed with 10')
            case 11:
                raise ValueError('Credential apply failed with 11')
            case 12:
                raise ValueError('Credential apply failed with 12')
            case 13:
                raise ValueError('Credential apply failed with 13')
            case 14:
                raise ValueError('Credential apply failed with 14')
            case 15:
                raise ValueError('Credential apply failed with 15')

        return super().form_valid(form)


class SetupWizardTlsServerCredentialApplyCancelView(View):
    http_method_names = ['get']

    def get(self, *args, **kwargs):
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        TrustStoreModel.objects.all().delete()
        CertificateModel.objects.all().delete()
        TrustpointTlsServerCredentialModel.objects.all().delete()

        if not SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY_CANCEL.exists():
            raise ValueError(str(SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY_CANCEL))

        # TODO(AlexHx8472): Exception Handling
        proc = subprocess.run(['sudo', f'{SCRIPT_WIZARD_TLS_SERVER_CREDENTIAL_APPLY_CANCEL}'])

        # TODO(AlexHx8472): Exception Handling
        match proc.returncode:
            case 1:
                raise ValueError('Initial failed with 1')
            case 2:
                raise ValueError('Initial failed with 2')
            case 3:
                raise ValueError('Initial failed with 3')
            case 4:
                raise ValueError('Initial failed with 4')

        messages.add_message(self.request, messages.INFO, 'Generation of the TLS-Server credential canceled.')

        return redirect('setup_wizard:initial', permanent=False)


class SetupWizardDemoDataView(FormView):
    http_method_names = ['get', 'post']
    form_class = EmptyForm
    template_name = 'setup_wizard/demo_data.html'
    success_url = reverse_lazy('setup_wizard:create_super_user')

    def get(self, *args, **kwargs):
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_DEMO_DATA:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().get(*args, **kwargs)

    def post(self, *args, **kwargs):
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_DEMO_DATA:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().post(*args, **kwargs)

    def _execute_state_bump(self):
        if not SCRIPT_WIZARD_DEMO_DATA.exists():
            raise ValueError(str(SCRIPT_WIZARD_DEMO_DATA))

        # TODO(AlexHx8472): Exception Handling
        proc = subprocess.run(['sudo', f'{SCRIPT_WIZARD_DEMO_DATA}'])

        # TODO(AlexHx8472): Exception Handling
        match proc.returncode:
            case 1:
                raise ValueError('Initial failed with 1')
            case 2:
                raise ValueError('Initial failed with 2')
            case 3:
                raise ValueError('Initial failed with 3')
            case 4:
                raise ValueError('Initial failed with 4')

    def form_valid(self, form):
        if 'without-demo-data' in self.request.POST:
            self._execute_state_bump()
            return super().form_valid(form)

        elif 'with-demo-data' in self.request.POST:
            call_command('add_domains_and_devices')
            self._execute_state_bump()
            return super().form_valid(form)

        messages.add_message(
            self.request,
            messages.ERROR,
            'Failed to pre-populate the database with demo data.')
        return redirect('setup_wizard:demo_data', permanent=False)


class SetupWizardCreateSuperUserView(FormView):
    http_method_names = ['get', 'post']
    form_class = UserCreationForm
    template_name = 'setup_wizard/create_super_user.html'
    success_url = reverse_lazy('users:login')


    def get(self, *args, **kwargs):
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_CREATE_SUPER_USER:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().get(*args, **kwargs)

    def post(self, *args, **kwargs):
        if not DOCKER_CONTAINER:
            return redirect('users:login', permanent=False)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state != SetupWizardState.WIZARD_CREATE_SUPER_USER:
            return StartupWizardRedirect.redirect_by_state(wizard_state)

        return super().post(*args, **kwargs)

    def _execute_state_bump(self):
        if not SCRIPT_WIZARD_CREATE_SUPER_USER.exists():
            raise ValueError(str(SCRIPT_WIZARD_CREATE_SUPER_USER))

        # TODO(AlexHx8472): Exception Handling
        proc = subprocess.run(['sudo', f'{SCRIPT_WIZARD_CREATE_SUPER_USER}'])

        # TODO(AlexHx8472): Exception Handling
        match proc.returncode:
            case 1:
                raise ValueError('Initial failed with 1')
            case 2:
                raise ValueError('Initial failed with 2')
            case 3:
                raise ValueError('Initial failed with 3')
            case 4:
                raise ValueError('Initial failed with 4')

    def form_valid(self, form):
        username = form.cleaned_data['username']
        password = form.cleaned_data['password1']
        call_command('createsuperuser', interactive=False, username=username, email='')
        user = User.objects.get(username=username)
        user.set_password(password)
        user.save()
        messages.add_message(self.request, messages.SUCCESS, 'Successfully created super-user.')

        self._execute_state_bump()

        return super().form_valid(form)
