from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .models import SecurityConfig
from .views import SecurityLevelMixin


@receiver(post_save, sender=SecurityConfig)
@receiver(post_delete, sender=SecurityConfig)
def update_security_level(sender, instance, **kwargs) -> None:
    SecurityLevelMixin.refresh_security_level_instance()
