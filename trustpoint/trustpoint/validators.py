from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def validate_isidentifer(value: str) -> None:
    if not value.isidentifier():
        raise ValidationError(
            _('Must start with a letter and only contain letters, numbers and underscores.'))
