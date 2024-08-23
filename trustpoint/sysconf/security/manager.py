from sysconf.models import SecurityConfig

from . import SecurityFeatures


class SecurityManager:

    low_features = (SecurityFeatures.LOCAL_ROOT_CA, SecurityFeatures.LOG_ACCESS)
    medium_features = (SecurityFeatures.LOG_ACCESS, )
    high_features = ()
    highest_features = ()

    @classmethod
    def is_feature_allowed(cls, feature_name: SecurityFeatures,  sec_level: str):
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
