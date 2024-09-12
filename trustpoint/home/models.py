"""Module that contains all models corresponding to the devices app."""

from __future__ import annotations

import logging

from devices.models import Device
from django.db import models
from django.utils.translation import gettext_lazy as _
from pki.models import CertificateModel, DomainModel, IssuingCaModel

log = logging.getLogger('tp.home')


class NotificationStatus(models.Model):
    """Model representing a status a notification can have."""

    class StatusChoices(models.TextChoices):
        """Status Types"""
        NEW = 'NEW', _('New')
        CONFIRMED = 'CONF', _('Confirmed')
        IN_PROGRESS = 'PROG', _('In Progress')
        SOLVED = 'SOLV', _('Solved')
        NOT_SOLVED = 'NOSOL', _('Not Solved')
        ESCALATED = 'ESC', _('Escalated')
        SUSPENDED = 'SUS', _('Suspended')
        REJECTED = 'REJ', _('Rejected')
        DELETED = 'DEL', _('Deleted')
        CLOSED = 'CLO', _('Closed')
        ACKNOWLEDGED = 'ACK', _('Acknowledged')
        FAILED = 'FAIL', _('Failed')
        EXPIRED = 'EXP', _('Expired')
        PENDING = 'PEND', _('Pending')

    status = models.CharField(max_length=20, choices=StatusChoices, unique=True)

    def __str__(self) -> str:
        """Returns a human-readable string."""
        return self.get_status_display()


class NotificationMessage(models.Model):
    """Message Model for Notifications with Short and Optional Long Descriptions."""
    short_description = models.CharField(max_length=255)
    long_description = models.CharField(max_length=65536, default='No description provided')

    def __str__(self) -> str:
        """Returns a human-readable string."""
        return self.short_description[:50]


class NotificationModel(models.Model):
    """Notifications Model."""

    class NotificationTypes(models.TextChoices):
        """Supported Notification Types."""

        SETUP = 'SET', _('SETUP')
        #DEBUG = 'DEB', _('DEBUG')
        INFO = 'INF', _('INFO')
        WARNING = 'WAR', _('WARNING')
        CRITICAL = 'CRI', _('CRITICAL')

    class NotificationSource(models.TextChoices):
        """Origin of the Notification."""
        SYSTEM = 'S', _('System')
        DOMAIN = 'D', _('Domain')
        DEVICE = 'E', _('Device')
        ISSUING_CA = 'I', _('Issuing CA')
        CERTIFICATE = 'C', _('Certificate')

    notification_type = models.CharField(
        max_length=3,
        choices=NotificationTypes.choices,
        default=NotificationTypes.INFO
    )

    notification_source = models.CharField(
        max_length=1,
        choices=NotificationSource.choices,
        default=NotificationSource.SYSTEM
    )

    domain = models.ForeignKey(
        DomainModel,
        on_delete=models.SET_NULL,
        blank=True, null=True,
        related_name='notifications')

    certificate = models.ForeignKey(
        CertificateModel,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='notifications')

    device = models.ForeignKey(
        Device,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='notifications')

    issuing_ca = models.ForeignKey(
        IssuingCaModel,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='notifications')

    event = models.CharField(max_length=255,
                             blank=True,
                             null=True)

    message = models.ForeignKey(
        NotificationMessage,
        on_delete=models.CASCADE,
        related_name='notifications')

    statuses = models.ManyToManyField(
        NotificationStatus,
        related_name='notifications')

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        """Returns a human-readable string."""
        return f'{self.get_notification_type_display()} - {self.message.short_description[:20]}'
