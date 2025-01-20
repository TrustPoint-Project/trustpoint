Feature: Identity Management via TPC_Web and TPC_CLI
  As a registered admin
  I want to create, view, edit, and delete digital identities
  So that I can manage them efficiently using TPC_Web and TPC_CLI

  Background:
    Given the admin is registered and logged into the system
    And the TPC_Web and TPC_CLI services are running

  @create_identity
  Scenario Outline: Create an identity
    When the admin opens <component>
    And the admin creates an identity using <method>
    Then the identity should be created and visible in the list of identities
    And the system should display the identity's details

    Examples:
      | component | method     |
      | TPC_Web   | web forms  |
      | TPC_CLI   | CLI command |

  @edit_identity
  Scenario Outline: Edit an identity
    When the admin opens <component>
    And the admin navigates to the list of identities
    And the admin edits an identity using <method>
    Then the identity should be updated and visible with the new values
    And the system should display the updated identity details

    Examples:
      | component | method     |
      | TPC_Web   | web forms  |
      | TPC_CLI   | CLI command |

  @delete_identity
  Scenario Outline: Delete an identity
    When the admin opens <component>
    And the admin navigates to the list of identities
    And the admin deletes an identity using <method>
    Then the identity should no longer appear in the list of identities
    And the system should confirm the identity has been deleted

    Examples:
      | component | method     |
      | TPC_Web   | web forms  |
      | TPC_CLI   | CLI command |
