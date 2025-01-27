from behave import given, when, then


@given("the admin user is logged into TPC_Web")
def step_admin_logged_in(context):
    """
    Logs the admin user into the TPC_Web interface.

    This step sets up the initial state for all scenarios, ensuring the admin is authenticated and on the TPC_Web dashboard.

    Steps:
    - Open the TPC_Web login page.
    - Enter valid credentials (username and password).
    - Submit the login form and verify the user is redirected to the dashboard.

    Raises:
        NotImplementedError: This step is not yet implemented.
    """
    raise NotImplementedError("Step not implemented: Admin login to TPC_Web.")


@then('the system should display a confirmation message')
def step_confirmation_message(context):
    """
    Verifies that the system displays a success message after an action.

    The confirmation message is expected to include the word "Success" or similar,
    indicating that the operation completed as intended.

    Raises:
        NotImplementedError: This step is not yet implemented.
    """
    raise NotImplementedError("Step not implemented: Confirmation message check.")


@then('the system should display an error message stating {error_message}')
def step_error_message(context, error_message):
    """
    Verifies that the system displays a specific error message.

    Args:
        error_message (str): The expected error message text.

    Raises:
        NotImplementedError: This step is not yet implemented.
    """
    raise NotImplementedError("Step not implemented: Error message check.")


@given("an API client is authenticated")
def step_api_client_authenticated(context):
    """
    Authenticates the API client to enable authorized interactions with the REST API.

    Steps:
    - Obtain an authentication token using valid credentials.
    - Attach the token to subsequent API requests in the Authorization header.

    Raises:
        NotImplementedError: This step is not yet implemented.
    """
    raise NotImplementedError("Step not implemented: API client authentication.")

@then('the API response should have a status code of {status_code}')
def step_verify_status_code(context, status_code):
    """
    Verifies the API response status code.

    Args:
        status_code (str): The expected status code.

    Raises:
        NotImplementedError: This step is not yet implemented.
    """
    raise NotImplementedError("Step not implemented: Verify API response status code.")

@then('the response payload should include an error message stating {error_message}')
def step_verify_error_message(context, error_message):
    """
    Verifies the response payload includes the specified error message.

    Args:
        error_message (str): The expected error message text.

    Raises:
        NotImplementedError: This step is not yet implemented.
    """
    raise NotImplementedError("Step not implemented: Verify error message in response payload.")


