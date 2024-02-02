from django.contrib import admin
from .models import LocalIssuingCa, IssuingCa


admin.site.register(IssuingCa)
admin.site.register(LocalIssuingCa)
