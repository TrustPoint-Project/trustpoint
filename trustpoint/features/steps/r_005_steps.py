from behave import given, when, then
from behave.api.pending_step import StepNotImplementedError

# Background steps
@given('I have a valid API key or token for authentication')
def step_valid_api_key(context):
    raise StepNotImplementedError('Implement API authentication setup with a valid key or token.')

@given('the TrustPoint database contains existing resources for testing')
def step_database_with_resources(context):
    raise StepNotImplementedError('Ensure the database has prepopulated resources for testing.')

# General REST API interactions
@given('I have a valid endpoint {endpoint}')
def step_valid_endpoint(context, endpoint):
    raise StepNotImplementedError(f"Set up a valid endpoint for testing: {endpoint}.")

@given('I have an invalid endpoint {endpoint}')
def step_invalid_endpoint(context, endpoint):
    raise StepNotImplementedError(f"Simulate an invalid endpoint for testing: {endpoint}.")

@given('I have a valid payload {payload}')
def step_valid_payload(context, payload):
    raise StepNotImplementedError(f"Prepare a valid payload: {payload}.")

@given('I have an invalid payload {payload}')
def step_invalid_payload(context, payload):
    raise StepNotImplementedError(f"Prepare an invalid payload: {payload}.")

@given('I have a valid partial payload {payload}')
def step_valid_partial_payload(context, payload):
    raise StepNotImplementedError(f"Prepare a valid partial payload: {payload}.")

@when('I send a GET request to {endpoint}')
def step_send_get_request(context, endpoint):
    raise StepNotImplementedError(f"Send a GET request to the endpoint: {endpoint}.")

@when('I send a POST request to {endpoint} with the payload')
def step_send_post_request(context, endpoint):
    raise StepNotImplementedError(f"Send a POST request to the endpoint: {endpoint} with the provided payload.")

@when('I send a PUT request to {endpoint} with the payload')
def step_send_put_request(context, endpoint):
    raise StepNotImplementedError(f"Send a PUT request to the endpoint: {endpoint} with the provided payload.")

@when('I send a DELETE request to {endpoint}')
def step_send_delete_request(context, endpoint):
    raise StepNotImplementedError(f"Send a DELETE request to the endpoint: {endpoint}.")

@when('I send a PATCH request to {endpoint} with the payload')
def step_send_patch_request(context, endpoint):
    raise StepNotImplementedError(f"Send a PATCH request to the endpoint: {endpoint} with the provided payload.")

# Response validations

@then('the response should include the requested resource details')
def step_response_includes_resource_details(context):
    raise StepNotImplementedError('Ensure the response includes details of the requested resource.')

@then('the response should include the created resource details')
def step_response_includes_created_resource(context):
    raise StepNotImplementedError('Ensure the response includes details of the created resource.')

@then('the response should include the updated resource details')
def step_response_includes_updated_resource(context):
    raise StepNotImplementedError('Ensure the response includes details of the updated resource.')

@then('the resource should no longer exist')
def step_resource_no_longer_exists(context):
    raise StepNotImplementedError('Verify that the deleted resource no longer exists.')

