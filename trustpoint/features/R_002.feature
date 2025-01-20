Feature: Certificate Management via TPC_Web and TPC_CLI
  As a registered admin
  I want to renew certificates for digital identities
  So that they remain valid and usable

  Background:
    Given the admin is registered and logged into the system
    And the TPC_Web and TPC_CLI services are running
    And there are existing identities with valid certificates

  @renew_certificate
  Scenario Outline: Renew a certificate
    When the admin opens <component>
    And the admin navigates to the list of identities
    And the admin renews the certificate of an identity using <method>
    Then the certificate of the identity should be renewed
    And the identity should have a usable and valid certificate

    Examples:
      | component | method     |
      | TPC_Web   | web forms  |
      | TPC_CLI   | CLI command |
