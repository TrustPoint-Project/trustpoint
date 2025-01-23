Feature: Certificate Lifecycle Management
  Enable complete lifecycle management for certificates, including renewal and revocation, as specified by R_004.

  Background:
    Given the server is running and reachable
    And I have the necessary client credentials for authentication
    And a valid certificate ID for an active certificate

  Scenario: Successful certificate renewal
    Given the certificate is about to expire
    When I send a renewal request for the certificate
    Then the server should process the renewal request
    And a renewed certificate should be issued with a new expiration date
    And the renewed certificate should be usable for secure communication

  Scenario Outline: Certificate renewal failure
    Given the certificate has already expired
    When I send a renewal request for the certificate
    Then the server should reject the renewal request
    And the response should indicate <error_reason>

    Examples:
      | error_reason          |
      | certificate_expired   |
      | invalid_request_format|

  Scenario: Successful certificate revocation
    Given a valid certificate ID for revocation
    When I send a revocation request for the certificate
    Then the server should revoke the certificate
    And the certificate status should change to revoked

  Scenario Outline: Revocation failure due to invalid certificate ID
    Given an invalid certificate ID
    When I send a revocation request for the certificate
    Then the server should reject the request
    And the response should indicate <error_reason>

    Examples:
      | error_reason                |
      | certificate_not_found       |
      | invalid_certificate_format  |
