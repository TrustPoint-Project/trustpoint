from functools import wraps

from django.core.exceptions import PermissionDenied

from sysconf.security.manager import SecurityManager


def security_level(feature_name):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            from sysconf.views import SecurityLevelMixin
            sec_level = SecurityLevelMixin.get_security_level()

            if not SecurityManager.is_feature_allowed(feature_name, sec_level):
                raise PermissionDenied('Security level does not allow access to feature: %s' % feature_name)
            return func(*args, **kwargs)

        return wrapper
    return decorator
