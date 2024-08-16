import abc


class Serializer(abc.ABC):
    """Abstract Base Class for all Serializer classes.

    Warnings:
        Serializer classes do not include any type of validation.
        They are merely converting between formats.

    **Serializer UML Class Diagram**

    .. uml::

        skinparam linetype ortho
        set separator none

        abstract class abc.ABC
        abstract class Serializer

        abc.ABC <|-- Serializer
    """
    pass
