"""Steps file for the corresponding feature file (R_013)"""  # noqa: INP001

import logging

from behave import runner
from bs4 import BeautifulSoup
from common_steps import step_admin_logged_in
from devices.models import IssuedCredentialModel, RemoteDeviceCredentialDownloadModel
from devices.tests.conftest import create_mock_models
from django.test import Client
from environment import given, then, when  # monkey-patched to not ignore exceptions

HTTP_OK = 200
HTTP_FOUND = 302
logger = logging.getLogger(__name__)


@given('an issued credential is successfully issued')
def step_given_issued_credential_exists(context: runner.Context) -> None:
    """Ensures a (mocked) issued credential exists.

    Args:
        context (runner.Context): Behave context.
    """
    try:
        models_dict = create_mock_models()
        context.issued_credential_model = IssuedCredentialModel.objects.get(id=models_dict['issued_credential'].id)
    except Exception as e:
        msg = f'Error: {e}'
        raise AssertionError(msg) from e
    context.download_view_url = f'/devices/credential-download/browser/{context.issued_credential_model.id}/'


@when('the admin visits the associated "Download on Device browser" view')
def step_when_admin_visits_the_given_view(context: runner.Context) -> None:
    """Ensures the admin visits the given view.

    Args:
        context (runner.Context): Behave context.
    """
    response = context.authenticated_client.get(context.download_view_url)
    assert response.status_code == HTTP_OK, 'Non-OK response code'

    context.otp_view_response = response.content


MIN_OTP_LENGTH = 8
MAX_OTP_LENGTH = 32


@then('a one-time password is displayed which can be used to download the credential from a remote device')
def step_then_an_otp_is_displayed(context: runner.Context) -> None:
    """Ensures that a one-time password is displayed which can be used to download the credential from a remote device.

    Args:
        context (runner.Context): Behave context.
    """
    soup = BeautifulSoup(context.otp_view_response, 'html.parser')
    element = soup.find(id='otp-display')
    assert element is not None, 'otp-display not in response'
    otp = element.text.strip()
    assert len(otp) >= MIN_OTP_LENGTH, 'OTP string shorter than 9 characters'
    assert len(otp) <= MAX_OTP_LENGTH, 'OTP string longer than 32 characters'

    context.otp = otp


@given('a correct one-time password')
def step_given_an_otp(context: runner.Context) -> None:
    """Ensures that a correct one-time password is given.

    Args:
        context (runner.Context): Behave context.
    """
    try:
        # This is ugly and a bunch of unnecessary repetition,
        # but there appears to be no way to make scenarios depend on each other
        # aka. "Given admin created one time password successfully"
        step_admin_logged_in(context)
        step_given_issued_credential_exists(context)
        step_when_admin_visits_the_given_view(context)
        step_then_an_otp_is_displayed(context)
    except Exception as e:
        msg = f'Error in Scenario prerequisites: {e}'
        raise AssertionError(msg) from e
    assert context.otp is not None, 'Correct OTP not in context'


@when('the user visits the "/devices/browser" endpoint and enters the OTP')
def step_when_user_visits_endpoint(context: runner.Context) -> None:
    """Ensures that the user visits the "/devices/browser" endpoint and enters the OTP.

    Args:
        context (runner.Context): Behave context.
    """
    context.unauthenticated_user_client = Client()
    response = context.unauthenticated_user_client.get('/devices/browser/')
    assert response.status_code == HTTP_OK, 'Non-OK response code, GET login page'
    assert 'id="id_otp"' in response.content.decode(), 'Page does not contain OTP input field'
    response = context.unauthenticated_user_client.post('/devices/browser/', {'otp': context.otp})
    if response.status_code == HTTP_FOUND:
        redirect_url = response.url
        logger.debug(f'Redirecting to {redirect_url}')  # noqa: G004
        if '?token=' in redirect_url:
            context.download_token = redirect_url.split('?token=')[-1]
        else:
            context.download_token = None
        if 'credential-download' in redirect_url:
            context.download_id = int(redirect_url.split('credential-download/')[1].split('/')[0])
        else:
            context.download_id = None
        response = context.unauthenticated_user_client.get(response.url)
    assert response.status_code == HTTP_OK, f'Non-OK response code {response.status_code}, POST otp'

    context.otp_post_view_response = response.content


@then('they will receive a page to select the format for the credential download')
def step_then_they_will_receive_page_to_select_the_format(context: runner.Context) -> None:
    """Ensures that they will receive a page to select the format for the credential download.

    Args:
        context (runner.Context): Behave context.
    """
    assert 'value="PEM_ZIP"' in context.otp_post_view_response.decode(), \
        'Page does not contain "Download as ZIP (PEM)" button'



@given('an incorrect one-time password')
def step_given_an_incorrect_otp(context: runner.Context) -> None:
    """Ensures that an incorrect one-time password is given.

    Args:
        context (runner.Context): Behave context.
    """
    context.otp = 'very_wrong_otp'


@then('they will receive a warning saying the OTP is incorrect')
def step_then_they_will_receive_a_warning(context: runner.Context) -> None:
    """Ensures that they will receive a warning saying the OTP is incorrect.

    Args:
        context (runner.Context): Behave context.
    """
    assert 'The provided password is not valid.' in context.otp_post_view_response.decode(), \
        'Page does not contain OTP error message'


@given('the user is on the credential download page')
def step_given_the_user_is_on_the_page(context: runner.Context) -> None:
    """Ensures that the user is on the credential download page.

    Args:
        context (runner.Context): Behave context.
    """
    try:
        # This is ugly and a bunch of unnecessary repetition,
        # but there appears to be no way to make scenarios depend on each other
        # aka. "Given admin created one time password successfully"
        # "And user entered the correct OTP and was forwarded to the format selection page"
        step_given_an_otp(context)
        step_when_user_visits_endpoint(context)
        step_then_they_will_receive_page_to_select_the_format(context)
    except Exception as e:
        msg = f'Error in Scenario prerequisites: {e}'
        raise AssertionError(msg) from e


@given('the download token is not yet expired')
def step_given_the_download_is_not_yet_expired(context: runner.Context) -> None:
    """Ensures that the download token is not yet expired.

    Args:
        context (runner.Context): Behave context.
    """
    assert context.download_token is not None, 'Download token not in context'
    assert not RemoteDeviceCredentialDownloadModel.objects.get(id=context.download_id).check_token('dummy_token'), \
        'Dummy token should not be valid'

    assert RemoteDeviceCredentialDownloadModel.objects.get(id=context.download_id).check_token(context.download_token),\
        'Actual token from URL should be valid'


@when('the user enters a password to encrypt the credential private key')
def step_when_the_user_enters_a_pw_to_encrypt_the_cred_priv_key(context: runner.Context) -> None:
    """Ensures that the user enters a password to encrypt the credential private key.

    Args:
        context (runner.Context): Behave context.
    """
    context.test_password = 'testing321321'  # noqa: S105


@when('selects a file format')
def step_when_user_selects_a_file(context: runner.Context) -> None:
    """Ensures that the user selects a file format.

    Args:
        context (runner.Context): Behave context.
    """
    url = f'/devices/browser/credential-download/{context.download_id}/?token={context.download_token}'
    post_data = {
        'password': context.test_password,
        'confirm_password': context.test_password,
        'file_format': 'PEM_ZIP'
    }
    download_response = context.unauthenticated_user_client.post(url, post_data)
    assert download_response.status_code == HTTP_OK, 'Non-OK response code'
    context.download_response = download_response


@then('the credential will be downloaded to their browser in the requested format')
def step_then_the_cred_will_be_downloaded(context: runner.Context) -> None:
    """Ensures that the credential will be downloaded to their browser in the requested format.

    Args:
        context (runner.Context): Behave context.
    """
    assert 'application/zip' in context.download_response['Content-Type'], 'Downloaded file is not a ZIP file'
    assert 'attachment; filename=' in context.download_response['Content-Disposition'], 'No filename in response'
