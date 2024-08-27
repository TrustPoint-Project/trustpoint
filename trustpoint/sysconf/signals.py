from django.core.cache import cache
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .models import SecurityConfig


@receiver(post_save, sender=SecurityConfig)
@receiver(post_delete, sender=SecurityConfig)
def update_security_level(sender, instance, **kwargs):
    if instance:
        security_level = instance.security_mode
        cache.set('security_level', security_level)
    else:
        cache.delete('security_level')
