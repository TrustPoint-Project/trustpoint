from __future__ import annotations

from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


class UniqueNameValidator(RegexValidator):

    form_label = _(
        '(Must start with a letter. Can only contain letters, digits, underscores and hyphens)')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(
            regex=r'^[a-zA-Z]+[a-zA-Z0-9_-]+$',
            message=_(
                f'Enter a valid unique name. {self.form_label}.'),
            code='invalid_unique_name'
        )


class UniqueNameLowerCaseValidator(RegexValidator):

    form_label = _(
        '(Must start with a letter. Can only contain lower case letters, digits, underscores and hyphens)')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(
            regex=r'^[a-z]+[a-z0-9_-]+$',
            message=_(
                f'Enter a valid unique name. {self.form_label}.'),
            code='invalid_unique_name'
        )