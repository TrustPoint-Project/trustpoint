"""Views for the users application."""
from __future__ import annotations

from django.contrib.auth.views import LoginView
from django.contrib import messages


from setup_wizard import SetupWizardState
from setup_wizard.views import StartupWizardRedirect


class TrustpointLoginView(LoginView):
    http_method_names = ['get', 'post']

    def get(self, *args, **kwargs):
        # clears all messages
        for _ in messages.get_messages(self.request):
            pass

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state == SetupWizardState.WIZARD_COMPLETED:
            return super().get(*args, **kwargs)

        return StartupWizardRedirect.redirect_by_state(wizard_state)

    def post(self, *args, **kwargs):
        # clears all messages
        for _ in messages.get_messages(self.request):
            pass

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state == SetupWizardState.WIZARD_COMPLETED:
            return super().post(*args, **kwargs)

        return StartupWizardRedirect.redirect_by_state(wizard_state)
