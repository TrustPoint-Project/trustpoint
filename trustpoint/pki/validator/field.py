from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _


class UniqueNameValidator(RegexValidator):

    def __init__(self, *args, **kwargs):
        super().__init__(
            regex=r'^[a-z0-9_-]+$',
            message=_(
                'Enter a valid unique name. '
                'Must start with a letter [A-Za-zA-Z]'
                'Can only contain letters [A-Za-z], digits [0-9] and underscores [_].'),
            code='invalid_unique_name'
        )
