from django.contrib import admin

from .models import PersonalAccessToken

class PersonalAccessTokenAdmin(admin.ModelAdmin):
    def get_readonly_fields(self, request, obj=None):
        """Make the user field non-editable on update"""
        defaults = super().get_readonly_fields(request, obj=obj)
        if obj:  # if we are updating an object
            defaults = tuple(defaults) + ('user', )  
        return defaults
    
admin.site.register(PersonalAccessToken, PersonalAccessTokenAdmin)