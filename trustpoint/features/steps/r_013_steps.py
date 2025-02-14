"""Steps file for the corresponding feature file (R_013)"""

import logging

from behave import given, runner, then, when
from devices.models import IssuedCredentialModel
from devices.tests.conftest import create_mock_models

HTTP_OK = 200
logger = logging.getLogger(__name__)


@given('an issued credential with ID {id} is successfully issued')
def step_impl(context: runner.Context, id: int) -> None:  # noqa: A002
    """Ensures an issued credential with the given ID exists.

    Args:
        context: the behave context
        id: the id
    """
    try:
        models_dict = create_mock_models()
        context.issued_credential_model = IssuedCredentialModel.objects.get(id=models_dict['issued_credential'].id)
    except Exception as e:  # noqa: BLE001
        assert False, f'Error: {e}'  # noqa: PT015, B011, PT017
    context.download_view_url = f'/devices/credential-download/browser/{context.issued_credential_model.id}/'


@when('the admin visits the associated "Download on Device browser" view')
def step_impl(context: runner.Context) -> None:  # noqa: F811
    """Ensures teh admin visits the given view.

    Args:
        context: the behave context
    """
    response = context.authenticated_client.get(context.download_view_url)
    assert response.status_code == HTTP_OK, 'Non-OK response code'

    assert 'id="otp-display"' in response.content.decode(), 'otp-display not in response'


@then('a one-time password is displayed which can be used to download the credential from a remote device')
def step_impl(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that a one-time password is displayed which can be used to download the credential from a remote device.

    Args:
        context: the behave context
    """
    msg = (
        'STEP: Then a one-time password is displayed which can be used to download the credential from a remote device'
    )
    assert False, msg  # noqa: PT015, B011


@given('a correct one-time password')
def step_impl(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that a correct one-time password is given.

    Args:
        context: the behave context
    """
    msg = 'STEP: Given a correct one-time password'
    assert False, msg  # noqa: PT015, B011


@when('the user visits the "/devices/browser" endpoint and enters the OTP')
def step_impl(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the user visits the "/devices/browser" endpoint and enters the OTP.

    Args:
        context: the behave context
    """
    msg = 'STEP: When the user visits the "/devices/browser" endpoint and enters the OTP'
    assert False, msg  # noqa: PT015, B011


@then('they will receive a page to select the format for the credential download')
def step_impl(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that they will receive a page to select the format for the credential download.

    Args:
        context: the behave context
    """
    msg = 'STEP: Then they will receive a page to select the format for the credential download'
    assert False, msg  # noqa: PT015, B011


@given('an incorrect one-time password')
def step_impl(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that an incorrect one-time password is given.

    Args:
        context: the behave context
    """
    msg = 'STEP: Given an incorrect one-time password'
    assert False, msg  # noqa: PT015, B011


@then('they will receive a warning saying the OTP is incorrect')
def step_impl(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that they will receive a warning saying the OTP is incorrect.

    Args:
        context: the behave context
    """
    msg = 'STEP: Then they will receive a warning saying the OTP is incorrect'
    assert False, msg  # noqa: PT015, B011


@given('the user is on the credential download page')
def step_impl(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the user is on the credential download page.

    Args:
        context: the behave context
    """
    msg = 'STEP: Given the user is on the credential download page'
    assert False, msg  # noqa: PT015, B011


@given('the download token is not yet expired')
def step_impl(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the download token is not yet expired.

    Args:
        context: the behave context
    """
    msg = 'STEP: Given the download token is not yet expired'
    assert False, msg  # noqa: PT015, B011


@when('the user enters a password to encrypt the credential private key')
def step_impl(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the user enters a password to encrypt the credential private key.

    Args:
        context: the behave context
    """
    msg = 'STEP: When the user enters a password to encrypt the credential private key'
    assert False, msg  # noqa: PT015, B011


@when('selects a file format')
def step_impl(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the user selects a file format.

    Args:
        context: the behave context
    """
    msg = 'STEP: When selects a file format'
    assert False, msg  # noqa: PT015, B011


@then('the credential will be downloaded to their browser in the requested format')
def step_impl(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures the the credential will be downloaded to their browser in the requested format.

    Args:
        context: the behave context
    """
    msg = 'STEP: Then the credential will be downloaded to their browser in the requested format'
    assert False, msg  # noqa: PT015, B011
