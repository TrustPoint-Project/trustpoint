import logging

from behave import given, then, when
from behave.api.pending_step import StepNotImplementedError, PendingStepError
from devices.models import IssuedCredentialModel
from devices.tests.conftest import create_mock_models
from django.http.response import HttpResponse

HTTP_OK = 200

@given('an issued credential with ID {id} is successfully issued')
def step_impl(context, id: int):
    print('print test') # TODO: remove
    logging.warning('TODO: Logging test!')
    try:
        models_dict = create_mock_models()
        #try:
        context.issued_credential_model = IssuedCredentialModel.objects.get(id=models_dict['issued_credential'].id)
        #except IssuedCredentialModel.DoesNotExist as e:
        #    raise PendingStepError from e
    except Exception as e:
        assert False, f'Error: {e}'
    context.download_view_url = f'/devices/credential-download/browser/{context.issued_credential_model.id}/'


@when(u'the admin visits the associated "Download on Device browser" view')
def step_impl(context):
    print('URL test:', context.download_view_url)
    response = context.authenticated_client.get(context.download_view_url)
    assert response.status_code == HTTP_OK, 'Non-OK response code'

    print(type(response.content))
    assert 'id="otp-display"' in response.content.decode()


@then(u'a one-time password is displayed which can be used to download the credential from a remote device')
def step_impl(context):
    raise StepNotImplementedError(u'STEP: Then a one-time password is displayed which can be used to download the credential from a remote device')


@given(u'a correct one-time password')
def step_impl(context):
    raise StepNotImplementedError(u'STEP: Given a correct one-time password')


@when(u'the user visits the "/devices/browser" endpoint and enters the OTP')
def step_impl(context):
    raise StepNotImplementedError(u'STEP: When the user visits the "/devices/browser" endpoint and enters the OTP')


@then(u'they will receive a page to select the format for the credential download')
def step_impl(context):
    raise StepNotImplementedError(u'STEP: Then they will receive a page to select the format for the credential download')


@given(u'an incorrect one-time password')
def step_impl(context):
    raise StepNotImplementedError(u'STEP: Given an incorrect one-time password')


@then(u'they will receive a warning saying the OTP is incorrect')
def step_impl(context):
    raise StepNotImplementedError(u'STEP: Then they will receive a warning saying the OTP is incorrect')


@given(u'the user is on the credential download page')
def step_impl(context):
    raise StepNotImplementedError(u'STEP: Given the user is on the credential download page')


@given(u'the download token is not yet expired')
def step_impl(context):
    raise StepNotImplementedError(u'STEP: Given the download token is not yet expired')


@when(u'the user enters a password to encrypt the credential private key')
def step_impl(context):
    raise StepNotImplementedError(u'STEP: When the user enters a password to encrypt the credential private key')


@when(u'selects a file format')
def step_impl(context):
    raise StepNotImplementedError(u'STEP: When selects a file format')


@then(u'the credential will be downloaded to their browser in the requested format')
def step_impl(context):
    raise StepNotImplementedError(u'STEP: Then the credential will be downloaded to their browser in the requested format')
