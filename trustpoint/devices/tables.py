"""Module that contains all tables corresponding to the devices application."""


from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
import datetime

from devices.models import DeviceModel, IssuedCredentialModel

if TYPE_CHECKING:
    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}

class DeviceTable(tables.Table):
    """Table representation of the Certificate model."""

    class Meta:
        """Meta table configurations."""

        model = DeviceModel
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no Devices available.')
        empty_text = format_html('<div class="text-center">{}</div>', _msg)

        fields = (
            'row_checkbox',
            'unique_name',
            'domain',
            'serial_number',
            'created_at',
            'updated_at',
            'onboarding_protocol',
            'onboarding_status',
            'onboarding',
            'clm',
            'details',
            'configure',
            'revoke',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    onboarding_status = tables.Column(empty_values=(), orderable=True, verbose_name=_('Onboarding Status'))
    onboarding = tables.Column(empty_values=(), orderable=False, verbose_name=_('Onboarding'))
    clm = tables.Column(empty_values=(), orderable=False, verbose_name=_('Certificate Lifecycle Management'))
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    configure = tables.Column(empty_values=(), orderable=False, verbose_name=_('Configure'))
    revoke = tables.Column(empty_values=(), orderable=False, verbose_name=_('Revoke'))

    @staticmethod
    def render_onboarding_status(record: DeviceModel) -> SafeString:
        if record.onboarding_status == DeviceModel.OnboardingStatus.NO_ONBOARDING:
            return format_html('')
        return format_html(record.get_onboarding_status_display())

    @staticmethod
    def render_onboarding(record: DeviceModel) -> SafeString:
        """Creates the html hyperlink for the onboarding-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        if not record.domain:
            return format_html(
                '<span>{}</span>',_('No Domain configured.'))
        if not record.domain.issuing_ca:
            return format_html(
                '<span>{}</span>', _('No Issuing CA configured.')
            )
        if (record.onboarding_status == DeviceModel.OnboardingStatus.PENDING
                and record.onboarding_protocol == DeviceModel.OnboardingProtocol.MANUAL):
            return format_html(
                '<a href="onboarding/{}/manual/issue-domain-credential" class="btn btn-primary tp-table-btn w-100">{}</a>',
                record.pk, _('Start Onboarding'))
        return format_html('')

    @staticmethod
    def render_clm(record: DeviceModel) -> SafeString:
        valid_onboarding_statuses = (
            DeviceModel.OnboardingStatus.NO_ONBOARDING,
            DeviceModel.OnboardingStatus.ONBOARDED
        )
        if record.onboarding_status in valid_onboarding_statuses:
            return format_html(
                '<a href="certificate-lifecycle-management/{}/" class="btn btn-primary tp-table-btn w-100">{}</a>',
                record.pk,
                _('Manage Issued Certificates'))
        return format_html('')

    @staticmethod
    def render_details(record: DeviceModel) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record: The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn w-100">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_configure(record: DeviceModel) -> SafeString:
        """Creates the html hyperlink for the configure-view.

        Args:
            record: The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the configure-view.
        """
        return format_html('<a href="configure/{}/" class="btn btn-primary tp-table-btn w-100">{}</a>', record.pk, _('Configure'))

    @staticmethod
    def render_revoke(record: DeviceModel) -> SafeString:
        """Creates the html hyperlink for the revoke-view.

        Args:
            record: The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the revoke-view.
        """
        return format_html('<a href="revoke/{}/" class="btn btn-danger tp-table-btn w-100">{}</a>',
                           record.pk, _('Revoke'))


class DeviceDomainCredentialsTable(tables.Table):
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
        return format_html(
            '<a href="/devices/domain-credential-download/{}/"'
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

class DeviceApplicationCertificatesTable(tables.Table):
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
    def render_common_name(record: IssuedCredentialModel) -> SafeString:
        return format_html(record.credential.certificate.common_name)

    @staticmethod
    def render_credential_type(record: IssuedCredentialModel) -> SafeString:
        return format_html(record.get_issued_credential_type_display())

    @staticmethod
    def render_credential_purpose(record: IssuedCredentialModel) -> SafeString:
        return format_html(record.get_issued_credential_purpose_display())

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
        """Creates the html hyperlink for the details-view.

        Args:
            record: The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html(
            '<a href="/devices/application-credential-download/{}/" '
            'class="btn btn-primary tp-table-btn w-100">{}</a>',
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
