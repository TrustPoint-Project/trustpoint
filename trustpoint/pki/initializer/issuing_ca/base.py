import abc

from . import Initializer, InitializerError


class IssuingCaInitializer(Initializer, abc.ABC):
    _unique_name: str
    _is_initialized: bool = False

class IssuingCaInitializerError(InitializerError):
    pass
