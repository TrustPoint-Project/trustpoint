from behave import when, then, given
from behave.api.pending_step import StepNotImplementedError


@when('the API client sends a POST request to "/api/identities" with the following payload:')
def step_post_identity(context, payload):
    """
    Sends a POST request to the REST API to create a new identity.

    The payload contains the fields required to define the identity.

    Args:
        context (behave.runner.Context): Behave context containing the payload table.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    raise StepNotImplementedError("Step not implemented: POST request to create an identity.")


@when('the API client sends a GET request to "/api/identities/<identifier>"')
def step_get_identity(context, identifier):
    """
    Sends a GET request to the REST API to retrieve an identity by its identifier.

    Args:
        identifier (str): The unique identifier of the identity.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    raise StepNotImplementedError("Step not implemented: GET request to retrieve an identity.")


@when('the API client sends a PUT request to "/api/identities/<identifier>" with the following payload:')
def step_put_identity(context, identifier, payload):
    """
    Sends a PUT request to update an existing identity.

    Args:
        identifier (str): The unique identifier of the identity.
        context (behave.runner.Context): Behave context containing the payload table.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    raise StepNotImplementedError("Step not implemented: PUT request to update an identity.")


@when('the API client sends a DELETE request to "/api/identities/<identifier>"')
def step_delete_identity(context, identifier):
    """
    Sends a DELETE request to remove an identity by its identifier.

    Args:
        identifier (str): The unique identifier of the identity.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    raise StepNotImplementedError("Step not implemented: DELETE request to remove an identity.")


@when('the API client sends a GET request to "/api/identities" without authentication')
def step_get_without_auth(context):
    """
    Sends a GET request to the REST API without including authentication credentials.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    raise StepNotImplementedError("Step not implemented: Unauthorized GET request.")


@then('the response payload should include the created identity with:')
def step_verify_created_identity(context, payload):
    """
    Verifies the response payload includes the expected fields for a newly created identity.

    Args:
        context (behave.runner.Context): Behave context containing the expected identity fields.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    raise StepNotImplementedError("Step not implemented: Verify response payload for created identity.")


@then('the response payload should include the identity with:')
def step_verify_retrieved_identity(context, payload):
    """
    Verifies the response payload includes the expected fields for the retrieved identity.

    Args:
        context (behave.runner.Context): Behave context containing the expected identity fields.

    Raises:
        StepNotImplementedError: This step is not yet implemented.
    """
    raise StepNotImplementedError("Step not implemented: Verify response payload for retrieved identity.")


@given('the identity {identity} exists')
def step_impl(context, identity):
    raise StepNotImplementedError(u'STEP: Given the identity {identity} exists')


@when('the API client sends a GET request to "/api/identities/{identity}')
def step_impl(context, identity):
    raise StepNotImplementedError(f'STEP: When the API client sends a GET request to "/api/identities/{identity}')


@when('the API client sends a PUT request to "/api/identities/{identity} with the following payload:')
def step_impl(context, identity, payload):
    raise StepNotImplementedError(
        f'STEP: When the API client sends a PUT request to "/api/identities/{identity} with the following payload: {payload}')


@then('the response payload should include the updated identity with:')
def step_impl(context, payload):
    raise StepNotImplementedError(
        f'STEP: Then the response payload should include the updated identity with: {payload}')


@when('the API client sends a DELETE request to "/api/identities/{identity}')
def step_impl(context, identity):
    raise StepNotImplementedError(f'STEP: When the API client sends a DELETE request to "/api/identities/{identity}')


@then(u'the identity {identity} should no longer exist')
def step_impl(context, identity):
    raise StepNotImplementedError(f'STEP: Then the identity {identity} should no longer exist')
