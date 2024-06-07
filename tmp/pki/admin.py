"""Module contains registrations of models with the admin interface."""


from django.contrib import admin

from .models import EndpointProfile, IssuingCa, TestA, TestB, Certificate

admin.site.register(IssuingCa)
admin.site.register(EndpointProfile)


class TestAAdmin(admin.ModelAdmin):
    readonly_fields = ('id',)


class TestBAdmin(admin.ModelAdmin):
    readonly_fields = ('id',)


admin.site.register(TestA, TestAAdmin)
admin.site.register(TestB, TestBAdmin)
admin.site.register(Certificate, TestBAdmin)
