"""Django Admin model registrations."""

from django.contrib import admin

from .models import NotificationMessageModel, NotificationModel, NotificationStatus


class NotificationStatusAdmin(admin.ModelAdmin):
    """NotificationStatusAdmin registers all."""

class NotificationModelAdmin(admin.ModelAdmin):
    """NotificationModelAdmin registers all."""

class NotificationMessageAdmin(admin.ModelAdmin):
    """NotificationMessageAdmin registers all."""


admin.site.register(NotificationStatus, NotificationStatusAdmin)
admin.site.register(NotificationModel, NotificationModelAdmin)
admin.site.register(NotificationMessageModel, NotificationMessageAdmin)
