"""pytest configuration for the tests in the PKI app."""

import pytest


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db: None) -> None:
    """Fixture to enable database access for all tests."""
