from __future__ import annotations


import abc
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from typing import Any


__all__ = [
    'FileBuilder'
]


class FileBuilder(abc.ABC):

    @staticmethod
    @abc.abstractmethod
    def build(*args: tuple[Any], **kwargs: dict[str, Any]) -> bytes:
        pass
