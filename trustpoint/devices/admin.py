"""Module contains registrations of models with the admin interface."""


from django.contrib import admin

from .models import Device

admin.site.register(Device)
