import abc

from django.core.exceptions import ValidationError


class InitializerError(ValidationError):
    pass


class Initializer(abc.ABC):
    """Base class for all Initializer classes."""

    @abc.abstractmethod
    def initialize(self):
        """Initializes the required objects and performs validations."""

    @abc.abstractmethod
    def save(self):
        """Saves the current state to DB, if it was successfully initialized and validated.

        Raises:
            InitializationException
        """
