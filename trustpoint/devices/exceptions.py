"""Module that contains all custom Exception classes for the devices app."""


from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


class DisplayError(ValueError):
    """Raised when some entry in the table cannot be rendered appropriately."""


class UnknownOnboardingStatusError(DisplayError):
    """Raised when an unknown onboarding status was found and thus cannot be rendered appropriately."""

    def __init__(self: UnknownOnboardingStatusError, *args: Any) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Unknown onboarding status. Failed to render entry in table.'
        super().__init__(exc_msg, *args)


class UnknownOnboardingProtocolError(DisplayError):
    """Raised when an unknown onboarding protocol was found and thus cannot be rendered appropriately."""

    def __init__(self: UnknownOnboardingProtocolError, *args: Any) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Unknown onboarding protocol. Failed to render entry in table.'
        super().__init__(exc_msg, *args)
