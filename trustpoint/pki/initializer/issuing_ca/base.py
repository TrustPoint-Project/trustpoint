import abc

from . import Initializer
from . import InitializerError



class IssuingCaInitializer(Initializer, abc.ABC):
    pass

class IssuingCaInitializerError(InitializerError):
    pass
