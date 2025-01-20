Feature: EST Protocol
    # Example feature file for testing a URL of the EST protocol.
    As a user of TrustPoint, I want to interact with the EST protocol endpoints
    so that I can enroll and manage certificates.

    Scenario: Enroll with valid CSR
        Given the EST server is running
        When I POST a valid CSR to "/.well-known/est/simpleenroll"
        Then I receive a 200 response
        And the response contains a valid certificate
