import logging

from django.core.cache import cache
from django.db.models.signals import post_delete, post_init, post_save
from django.dispatch import receiver
from pki.auto_gen_pki import AutoGenPki

from .models import SecurityConfig
from .security import SecurityModeChoices

log = logging.getLogger('tp.sysconf')

@receiver(post_save, sender=SecurityConfig)
@receiver(post_delete, sender=SecurityConfig)
def update_security_level(sender, instance, **kwargs):
    if instance:
        security_level = instance.security_mode
        cache.set('security_level', security_level)

        if instance.security_mode != instance._original_values['security_mode']:
            log.warning('! Security level changed from %s to %s !',
                        SecurityModeChoices(instance._original_values['security_mode']).label,
                        SecurityModeChoices(instance.security_mode).label)

        if instance.auto_gen_pki and instance._original_values['auto_gen_pki'] == False:
            AutoGenPki.enable_auto_gen_pki()
        elif not instance.auto_gen_pki and instance._original_values['auto_gen_pki'] == True:
            AutoGenPki.disable_auto_gen_pki()

        # save newly saved values as new original values
        save_original_values(sender, instance, **kwargs)
    else:
        cache.delete('security_level')



@receiver(post_init, sender=SecurityConfig)
def save_original_values(sender, instance, **kwargs):
    if instance:
        instance._original_values['security_mode'] = instance.security_mode
        instance._original_values['auto_gen_pki'] = instance.auto_gen_pki