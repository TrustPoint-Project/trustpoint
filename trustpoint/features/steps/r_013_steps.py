"""Steps file for the corresponding feature file (R_013)"""  # noqa: INP001

import logging

from behave import given, runner, then, when
from devices.models import IssuedCredentialModel
from devices.tests.conftest import create_mock_models

HTTP_OK = 200
logger = logging.getLogger(__name__)


@given('an issued credential with ID {id} is successfully issued')
def step_given_issued_credential_with_given_id_exists(context: runner.Context, id: int) -> None:  # noqa: A002, ARG001
    """Ensures an issued credential with the given ID exists.

    Args:
        context (runner.Context): Behave context.
        id (int): the id
    """
    try:
        models_dict = create_mock_models()
        context.issued_credential_model = IssuedCredentialModel.objects.get(id=models_dict['issued_credential'].id)
    except Exception as e:  # noqa: BLE001
        msg = f'Error: {e}'
        raise AssertionError(msg)  # noqa: B904
    context.download_view_url = f'/devices/credential-download/browser/{context.issued_credential_model.id}/'


@when('the admin visits the associated "Download on Device browser" view')
def step_when_admin_visits_the_given_view(context: runner.Context) -> None:
    """Ensures teh admin visits the given view.

    Args:
        context (runner.Context): Behave context.
    """
    response = context.authenticated_client.get(context.download_view_url)
    assert response.status_code == HTTP_OK, 'Non-OK response code'

    assert 'id="otp-display"' in response.content.decode(), 'otp-display not in response'


@then('a one-time password is displayed which can be used to download the credential from a remote device')
def step_then_an_otp_is_displayed(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that a one-time password is displayed which can be used to download the credential from a remote device.

    Args:
        context (runner.Context): Behave context.
    """
    msg = (
        'STEP: Then a one-time password is displayed which can be used to download the credential from a remote device'
    )
    raise AssertionError(msg)


@given('a correct one-time password')
def step_given_an_otp(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that a correct one-time password is given.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Given a correct one-time password'
    raise AssertionError(msg)


@when('the user visits the "/devices/browser" endpoint and enters the OTP')
def step_when_user_visits_endpoint(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the user visits the "/devices/browser" endpoint and enters the OTP.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When the user visits the "/devices/browser" endpoint and enters the OTP'
    raise AssertionError(msg)


@then('they will receive a page to select the format for the credential download')
def step_then_they_will_receive_page_to_select_the_format(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that they will receive a page to select the format for the credential download.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then they will receive a page to select the format for the credential download'
    raise AssertionError(msg)


@given('an incorrect one-time password')
def step_given_an_incorrect_otp(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that an incorrect one-time password is given.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Given an incorrect one-time password'
    raise AssertionError(msg)


@then('they will receive a warning saying the OTP is incorrect')
def step_then_they_will_receive_a_warning(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that they will receive a warning saying the OTP is incorrect.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then they will receive a warning saying the OTP is incorrect'
    raise AssertionError(msg)


@given('the user is on the credential download page')
def step_given_the_user_is_on_the_page(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the user is on the credential download page.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Given the user is on the credential download page'
    raise AssertionError(msg)


@given('the download token is not yet expired')
def step_given_the_download_is_not_yet_expired(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the download token is not yet expired.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Given the download token is not yet expired'
    raise AssertionError(msg)


@when('the user enters a password to encrypt the credential private key')
def step_when_the_user_enters_a_pw_to_encrypt_the_cred_priv_key(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the user enters a password to encrypt the credential private key.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When the user enters a password to encrypt the credential private key'
    raise AssertionError(msg)


@when('selects a file format')
def step_when_user_selects_a_file(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the user selects a file format.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: When selects a file format'
    raise AssertionError(msg)


@then('the credential will be downloaded to their browser in the requested format')
def step_when_the_cred_will_be_downloaded(context: runner.Context) -> None:  # noqa: ARG001
    """Ensures that the credential will be downloaded to their browser in the requested format.

    Args:
        context (runner.Context): Behave context.
    """
    msg = 'STEP: Then the credential will be downloaded to their browser in the requested format'
    raise AssertionError(msg)
