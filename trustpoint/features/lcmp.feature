# Lightweight Certificate Management Protocol (LCMP)
# This feature file tests core LCMP functionalities as defined in RFC 9483 (https://datatracker.ietf.org/doc/html/rfc9483#name-how-to-read-this-document).
# Each scenario corresponds to a critical aspect of the protocol, with references to relevant RFC sections.

Feature: Lightweight Certificate Management Protocol (LCMP)
  As an LCMP client
  I want to interact with the LCMP server to manage certificates
  So that I can ensure compliance with RFC 9483 and secure communication

  # Background: Common setup for all scenarios
  # This ensures the server is reachable and initializes common data.
  Background:
    Given the LCMP server is running and reachable
    And I have the necessary client credentials for authentication

  # Section 4 of RFC 9483 defines certificate request processing.
  # These scenarios test valid and invalid requests.
  @request_handling
  Scenario Outline: Certificate Request Handling
    Given I have a certificate signing request (CSR) with "<request_type>" parameters
    When I send the CSR to the LCMP server
    Then the server should return a response indicating "<expected_result>"
    And "<response_data>" should be included in the server's response

    Examples:
      | request_type | expected_result  | response_data                 |
      | valid        | success          | issued certificate           |
      | invalid      | error            | error code for "Invalid CSR" |

  # Section 6 of RFC 9483 specifies certificate revocation.
  # This tests revocation of valid and invalid certificates.
  @certificate_revocation
  Scenario Outline: Certificate Revocation
    Given I have a certificate ID for "<certificate_type>" certificate
    When I send a revocation request to the server
    Then the server should return a response indicating "<expected_result>"
    And the certificate should be "<revocation_status>"

    Examples:
      | certificate_type | expected_result | revocation_status |
      | valid            | success         | marked as revoked |
      | non-existent     | error           | not revoked       |

  # Section 7 discusses error handling.
  # This ensures LCMP handles various errors gracefully.
  @error_handling
  Scenario: Handle malformed requests
    Given I send a malformed request to the server
    When the server processes the request
    Then the server should return an error response
    And the error code should indicate "Bad Request"

  # Section 8 focuses on security.
  # This ensures authentication and encryption are enforced.
  @security
  Scenario Outline: Authentication and Authorization
    Given I attempt to send a request with "<auth_status>" credentials
    When the server processes the request
    Then the server should return "<expected_response>"

    Examples:
      | auth_status  | expected_response     |
      | valid        | success               |
      | missing      | error: Unauthorized   |
      | invalid      | error: Forbidden      |

  # Additional checks for compliance and robustness
  @robustness
  Scenario: Handle network unavailability
    Given the LCMP server is temporarily unreachable
    When I send a request
    Then the client should retry according to RFC guidelines
    And it should return an appropriate error if retries fail
