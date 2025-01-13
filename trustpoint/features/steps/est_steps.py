import json
from behave import given, when, then
from django.test import Client


# Example step file for the feature file testing the EST protocol.

@given('the EST server is running')
def step_impl(context):
    context.client = Client()


@when('I POST a valid CSR to "/.well-known/est/simpleenroll"')
def step_impl(context):
    csr = "-----BEGIN CERTIFICATE REQUEST-----\n..."  # Example CSR
    context.response = context.client.post(
        "/.well-known/est/simpleenroll",
        data=csr,
        content_type="application/pkcs10"
    )


@then('I receive a 200 response')
def step_impl(context):
    assert context.response.status_code == 200


@then('the response contains a valid certificate')
def step_impl(context):
    cert = context.response.content
    assert b"-----BEGIN CERTIFICATE-----" in cert
