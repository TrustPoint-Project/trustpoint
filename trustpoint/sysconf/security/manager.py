from django.core.cache import cache

from sysconf.models import SecurityConfig

from . import SecurityFeatures


class SecurityManager:

    highest_features = (SecurityFeatures.LOG_ACCESS, )
    high_features = (*highest_features, SecurityFeatures.ISSUING_CA_TABLE_VIEW, )
    medium_features = (*high_features, )
    low_features = (*medium_features, SecurityFeatures.LOCAL_ROOT_CA, )


    @classmethod
    def is_feature_allowed(cls, feature_name: SecurityFeatures):
        print(f'highest_features:  {cls.highest_features}')
        print(f'high_features:  {cls.high_features}')
        print(f'medium_features:  {cls.medium_features}')
        print(f'low_features:  {cls.low_features}')

        sec_level = cls.get_security_level()
        if sec_level == SecurityConfig.SecurityModeChoices.DEV:
            return True
        elif sec_level == SecurityConfig.SecurityModeChoices.LOW:
            return feature_name in cls.low_features
        elif sec_level == SecurityConfig.SecurityModeChoices.MEDIUM:
            return feature_name in cls.medium_features
        elif sec_level == SecurityConfig.SecurityModeChoices.HIGH:
            return feature_name in cls.high_features
        elif sec_level == SecurityConfig.SecurityModeChoices.HIGHEST:
            return feature_name in cls.highest_features
        return False

    @classmethod
    def get_security_level(cls):
        """Returns the security mode of the current security level instance.

        Returns:
        --------
        str
            The security mode of the current security level instance.
        """
        security_level = cache.get('security_level')
        if not security_level:
            cls._set_cache()
        return cache.get('security_level')

    @classmethod
    def _set_cache(cls) -> None:
        """Sets the security level in the cache by fetching it from the database."""
        current_sec_config = SecurityConfig.objects.first()
        if current_sec_config:
            cache.set('security_level', current_sec_config.security_mode)
