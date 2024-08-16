"""The base module provides abstract base Serializer classes."""

import abc


class Serializer(abc.ABC):
    """Abstract Base Class for all Serializer classes.

    Warnings:
        Serializer classes do not include any type of validation.
        They are merely converting between formats.
    """
    pass
