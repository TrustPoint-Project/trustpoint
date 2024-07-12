"""Module that contains all custom Exception classes for the devices app."""


from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

log = logging.getLogger('tp.devices')

class DisplayError(ValueError):
    """Raised when some entry in the table cannot be rendered appropriately."""

    def __init__(self: DisplayError, *args: Any) -> None:
        """Logs all exceptions inheriting from DisplayError."""
        super().__init__(*args)
        if args:
            log.error(args[0])


class UnknownOnboardingStatusError(DisplayError):
    """Raised when an unknown onboarding status was found and thus cannot be rendered appropriately."""

    def __init__(self: UnknownOnboardingStatusError, status: str ='', *args) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = f'Unknown onboarding status {status}. Failed to render entry in table.'
        super().__init__(exc_msg, *args)


class UnknownOnboardingProtocolError(DisplayError):
    """Raised when an unknown onboarding protocol was found and thus cannot be rendered appropriately."""

    def __init__(self: UnknownOnboardingProtocolError, protocol: str ='', *args: Any) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = f'Unknown onboarding protocol {protocol}. Failed to render entry in table.'
        super().__init__(exc_msg, *args)
