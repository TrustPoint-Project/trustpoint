"""Module that contains all models corresponding to the devices app."""

from __future__ import annotations

import logging

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from pki.models import DomainModel, CertificateModel, IssuingCaModel
from devices.models import Device

log = logging.getLogger('tp.home')


class NotificationStatus(models.Model):
    """Model representing a status a notification can have."""
    STATUS_CHOICES = [
        ('NEW', _('New')),
        ('CONFIRMED', _('Confirmed')),
        ('IN_PROGRESS', _('In Progress')),
        ('SOLVED', _('Solved')),
        ('ESCALATED', _('Escalated')),
        ('SUSPENDED', _('Suspended')),
        ('REJECTED', _('Rejected')),
        ('DELETED', _('Deleted')),
        ('CLOSED', _('Closed')),
        ('ACKNOWLEDGED', _('Acknowledged')),
        ('FAILED', _('Failed')),
        ('EXPIRED', _('Expired')),
        ('PENDING', _('Pending')),
    ]

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, unique=True)

    def __str__(self):
        return self.get_status_display()


class NotificationMessage(models.Model):
    """Message Model for Notifications with Short and Optional Long Descriptions."""
    short_description = models.CharField(max_length=255)
    long_description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.short_description[:50]


class NotificationModel(models.Model):
    """Notifications Model."""

    class NotificationTypes(models.TextChoices):
        """Supported Notification Types."""

        SETUP = 'SET', _('SETUP')
        DEBUG = 'DEB', _('DEBUG')
        INFO = 'INF', _('INFO')
        WARNING = 'WAR', _('WARNING')
        CRITICAL = 'CRI', _('CRITICAL')

    class NotificationSource(models.TextChoices):
        """Origin of the Notification."""
        SYSTEM = 'SYSTEM', _('System')
        DOMAIN = 'DOMAIN', _('Domain')
        DEVICE = 'DEVICE', _('Device')
        ISSUING_CA = 'CA', _('Issuing CA')
        CERTIFICATE = 'CERT', _('Certificate')

    notification_type = models.CharField(
        max_length=3,
        choices=NotificationTypes.choices,
        default=NotificationTypes.INFO
    )

    notification_source = models.CharField(
        max_length=10,
        choices=NotificationSource.choices,
        default=NotificationSource.SYSTEM
    )

    domain = models.ForeignKey(DomainModel,
                               on_delete=models.SET_NULL,
                               blank=True, null=True,
                               related_name='notifications')

    certificate = models.ForeignKey(CertificateModel,
                                    on_delete=models.SET_NULL,
                                    blank=True,
                                    null=True,
                                    related_name='notifications')
    device = models.ForeignKey(Device,
                               on_delete=models.SET_NULL,
                               blank=True,
                               null=True,
                               related_name='notifications')

    issuing_ca = models.ForeignKey(IssuingCaModel,
                                   on_delete=models.SET_NULL,
                                   blank=True,
                                   null=True,
                                   related_name='notifications')

    message = models.ForeignKey(NotificationMessage,
                                on_delete=models.CASCADE,
                                related_name='notifications')

    statuses = models.ManyToManyField(NotificationStatus,
                                      related_name='notifications')

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.get_notification_type_display()} - {self.message.short_description[:20]}"
