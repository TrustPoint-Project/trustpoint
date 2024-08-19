import abc

from django.core.exceptions import ValidationError


class InitializerError(ValidationError):
    pass


class Initializer(abc.ABC):

    @abc.abstractmethod
    def initialize(self):
        """Initializes the required objects and performs validations."""
        pass

    @abc.abstractmethod
    def save(self):
        """Saves the current state to DB, if it was successfully initialized and validated.

        Raises:
            InitializationException
        """
        pass
