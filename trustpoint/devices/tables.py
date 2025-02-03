"""Module that contains all tables corresponding to the devices application."""


from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.html import format_html, mark_safe
from django.utils.translation import gettext_lazy as _

from devices.models import DeviceModel, IssuedCredentialModel, TrustpointClientOnboardingProcessModel

if TYPE_CHECKING:
    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}

class DeviceCredentialsTableMixin:
    """Mixin providing common render methods for device domain and application credential tables."""

    @staticmethod
    def render_common_name(record: IssuedCredentialModel) -> SafeString:
        return format_html(record.credential.certificate.common_name)

    @staticmethod
    def render_issued_at(record: IssuedCredentialModel) -> datetime.datetime:
        return record.created_at

    @staticmethod
    def render_expiration_date(record: IssuedCredentialModel) -> datetime.datetime:
        return record.credential.certificate.not_valid_after
    
    @staticmethod
    def render_expires_in(record: IssuedCredentialModel) -> SafeString:
        now = datetime.datetime.now(datetime.timezone.utc)
        if now >= record.credential.certificate.not_valid_after:
            return format_html('Expired')
        expire_timedelta = record.credential.certificate.not_valid_after - now
        days = expire_timedelta.days
        hours, remainder = divmod(expire_timedelta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return format_html(f'{days} days, {hours}:{minutes}:{seconds}')
    
    @staticmethod
    def render_download(record: IssuedCredentialModel) -> SafeString:
        """Creates the html hyperlink for the download-view.

        Args:
            record: The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the download-view.
        """
        if record.credential.private_key is None:
            return format_html('')
        return format_html(
            '<a href="/devices/credential-download/{}/"'
            ' class="btn btn-primary tp-table-btn w-100">{}</a>',
           record.id, _('Download'))

    @staticmethod
    def render_revoke(record: IssuedCredentialModel) -> SafeString:
        """Creates the html hyperlink for the revoke-view.

        Args:
            record: The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the revoke-view.
        """
        return format_html('<a href="revoke/{}/" class="btn btn-danger tp-table-btn w-100">{}</a>',
                           record.pk, _('Revoke'))


class DeviceDomainCredentialsTable(DeviceCredentialsTableMixin, tables.Table):
    """Lists all domain credentials for a specific device."""

    class Meta:
        """Meta table configurations."""

        model = IssuedCredentialModel
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no issued certificates available.')
        empty_text = format_html('<div class="text-center">{}</div>', _msg)

        fields = (
            'domain',
            'common_name',
            'issued_at',
            'expiration_date',
            'expires_in',
            'download',
            'revoke',
        )

    issued_at = tables.DateTimeColumn(empty_values=(), orderable=True, verbose_name=_('Issued At'))
    common_name = tables.DateTimeColumn(empty_values=(), orderable=True, verbose_name=_('Common Name (CN)'))
    expiration_date = tables.DateTimeColumn(empty_values=(), orderable=True, verbose_name=_('Expiration Date'))
    expires_in = tables.DateTimeColumn(empty_values=(), orderable=True, verbose_name=_('Expires In'))
    download = tables.Column(empty_values=(), orderable=False, verbose_name=_('Download'))
    revoke = tables.Column(empty_values=(), orderable=False, verbose_name=_('Revoke'))


class DeviceApplicationCertificatesTable(DeviceCredentialsTableMixin, tables.Table):
    """Lists all issued application certificates for a specific device."""

    class Meta:
        """Meta table configurations."""

        model = IssuedCredentialModel
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no issued certificates available.')
        empty_text = format_html('<div class="text-center">{}</div>', _msg)

        fields = (
            'common_name',
            'credential_type',
            'credential_purpose',
            'domain',
            'issued_at',
            'expiration_date',
            'expires_in',
            'download',
            'revoke',
        )

    issued_at = tables.DateTimeColumn(empty_values=(), orderable=True, verbose_name=_('Issued At'))
    common_name = tables.DateTimeColumn(empty_values=(), orderable=True, verbose_name=_('Common Name (CN)'))
    credential_type = tables.Column(empty_values=(), orderable=True, verbose_name=_('Credential Type'))
    credential_purpose = tables.Column(empty_values=(), orderable=True, verbose_name=_('Credential Purpose'))
    expiration_date = tables.DateTimeColumn(empty_values=(), orderable=True, verbose_name=_('Expiration Date'))
    expires_in = tables.DateTimeColumn(empty_values=(), orderable=True, verbose_name=_('Expires In'))
    download = tables.Column(empty_values=(), orderable=False, verbose_name=_('Download'))
    revoke = tables.Column(empty_values=(), orderable=False, verbose_name=_('Revoke'))

    @staticmethod
    def render_credential_type(record: IssuedCredentialModel) -> SafeString:
        return format_html(record.get_issued_credential_type_display())

    @staticmethod
    def render_credential_purpose(record: IssuedCredentialModel) -> SafeString:
        return format_html(record.get_issued_credential_purpose_display())
