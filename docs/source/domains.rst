Domains
=======

Overview
--------

.. uml::
    :align: center

    class Domain {
        +unique_name : str
        +url_term : str
        +domain_config : DomainConfig
    }
    class IssuingCa