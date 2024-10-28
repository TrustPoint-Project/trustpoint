"""Signals for the sysconf app, e.g. on model save."""

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

        previous_security_mode = instance.get_original_value('security_mode')
        if instance.security_mode != previous_security_mode:
            log.warning('! Security level changed from %s to %s !',
                        SecurityModeChoices(previous_security_mode).label,
                        SecurityModeChoices(instance.security_mode).label)

        previous_auto_gen_pki = instance.get_original_value('auto_gen_pki')
        if instance.auto_gen_pki and previous_auto_gen_pki is False:
            AutoGenPki.enable_auto_gen_pki(instance.auto_gen_pki_key_algorithm)
        elif not instance.auto_gen_pki and previous_auto_gen_pki is True:
            AutoGenPki.disable_auto_gen_pki()

        # save newly saved values as new original values
        instance.update_original_values()
    else:
        cache.delete('security_level')
