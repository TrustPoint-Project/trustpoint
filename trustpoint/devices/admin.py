from django.contrib import admin
from .models import DeviceModel, IssuedDomainCredentialModel, IssuedApplicationCertificateModel


class DeviceModelAdmin(admin.ModelAdmin):
    pass

class IssuedDomainCredentialModelAdmin(admin.ModelAdmin):
    pass

class IssuedApplicationCertificateAdmin(admin.ModelAdmin):
    pass


admin.site.register(DeviceModel, DeviceModelAdmin)
admin.site.register(IssuedDomainCredentialModel, IssuedDomainCredentialModelAdmin)
admin.site.register(IssuedApplicationCertificateModel, IssuedApplicationCertificateAdmin)
