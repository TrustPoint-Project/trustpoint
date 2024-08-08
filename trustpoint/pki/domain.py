from .models import DomainModel


class Domain:

    _domain_model: DomainModel
    _cmp_is_enabled: bool = True
    _est_is_enabled: bool = True
    _rest_is_enabled: bool = True
    _scep_is_enabled: bool = False
    _acme_is_enabled: bool = False

    def __init__(self, domain_model: DomainModel) -> None:
        self._domain_model = domain_model

    @property
    def cmp_is_enabled(self) -> bool:
        # TODO
        return self._cmp_is_enabled

    @property
    def est_is_enabled(self) -> bool:
        # TODO
        return self._est_is_enabled

    @property
    def rest_is_enabled(self) -> bool:
        # TODO
        return self._rest_is_enabled

    @property
    def scep_is_enabled(self) -> bool:
        # TODO
        return self._scep_is_enabled

    @property
    def acme_is_enabled(self) -> bool:
        # TODO
        return self._acme_is_enabled

    def issue_certificate(self, certificate_request) -> None:
        pass
