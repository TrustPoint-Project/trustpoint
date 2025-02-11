"""File for steps which are used more often across multiple feature files."""

import logging
from typing import NoReturn

from behave import given, runner, step, then
from behave.exception import StepNotImplementedError

from django.test import Client

HTTP_OK = 200

@given('the TPC_Web application is running')
def step_tpc_web_running(context):
    """Verifies that the TPC_Web application is running.

    This step checks that the TPC_Web application is running and accessible at the expected URL.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    #context.response= context.test.client.get('/users/login/')
    response = Client().get('/users/login/')
    assert response.status_code == HTTP_OK
    #raise StepNotImplementedError('Step not implemented: TPC_Web application running check.')


@step('Commentary')
def commentary_step(context: runner.Context) -> None:
    """This method is used to provide the annotation "@Commentary" inside the feature files if additional text is needed to explain the step.

    Args:
        context: the context
    """
    # Get the correct step to override.
    scenario = context.formatter.current_scenario
    step = scenario.current_step
    # Override the step, this will prevent the decorator to be generated and only the text will show.
    step.commentary_override = True


@given('the admin user is logged into TPC_Web')
def step_admin_logged_in(context: runner.Context) -> NoReturn:
    """Logs the admin user into the TPC_Web interface.

    This step sets up the initial state for all scenarios, ensuring the admin is authenticated and on the TPC_Web dashboard.

    Steps:
    - Open the TPC_Web login page.
    - Enter valid credentials (username and password).
    - Submit the login form and verify the user is redirected to the dashboard.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    #scenario = context.formatter.current_scenario
    #step = scenario.current_step
    #msg = f'Step {step.name} started.'
    #logging.info(msg)

    c = Client()
    login_success = c.login(username='admin', password='testing321')  # noqa: S106
    #print(response.headers)
    response = c.get('/pki/certificates/') # authenticated page
    print(response.headers) # TODO: print doesn't work either
    logging.warning('TODO: Logging does not yet work!')
    assert login_success, 'Login unsuccessful'
    assert response.status_code == HTTP_OK

    context.authenticated_client = c



@then('the system should display a confirmation message')
def step_confirmation_message(context) -> NoReturn:
    """Verifies that the system displays a success message after an action.

    The confirmation message is expected to include the word "Success" or similar,
    indicating that the operation completed as intended.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    msg = 'Step not implemented: Confirmation message check.'
    raise StepNotImplementedError(msg)


@then('the system should display an error message stating {error_message}')
def step_error_message(context, error_message) -> NoReturn:
    """Verifies that the system displays a specific error message.

    Args:
        error_message (str): The expected error message text.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    logging.info('Hello World!')
    msg = 'Step not implemented: Error message check.'
    raise StepNotImplementedError(msg)


@given('an API client is authenticated')
def step_api_client_authenticated(context) -> NoReturn:
    """Authenticates the API client to enable authorized interactions with the REST API.

    Steps:
    - Obtain an authentication token using valid credentials.
    - Attach the token to subsequent API requests in the Authorization header.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    assert False, 'Expect Failing Step'
    msg = 'Step not implemented: API client authentication.'
    raise StepNotImplementedError(msg)


@then('the API response should have a status code of {status_code}')
def step_verify_status_code(context, status_code) -> NoReturn:
    """Verifies the API response status code.

    Args:
        status_code (str): The expected status code.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    msg = 'Step not implemented: Verify API response status code.'
    raise StepNotImplementedError(msg)


@then('the response payload should include an error message stating {error_message}')
def step_verify_error_message(context, error_message) -> NoReturn:
    """Verifies the response payload includes the specified error message.

    Args:
        error_message (str): The expected error message text.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    msg = 'Step not implemented: Verify error message in response payload.'
    raise StepNotImplementedError(msg)
