"""Contains validators that are available to all apps.

Validators that are specific to a single app shall be declared within the corresponding app.
"""


from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def validate_isidentifer(value: str) -> None:
    """Validates if value is a valid python identifier.

    Args:
        value (str): value to validate

    Returns:
        None: None if value is a python identifier

    Raises:
        ValidationError: If value is not a python identifier.

    """
    if not value.isidentifier():
        raise ValidationError(_('Must start with a letter and only contain letters, numbers and underscores.'))
