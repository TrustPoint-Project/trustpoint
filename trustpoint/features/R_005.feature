Feature: REST API
  Provide a REST API for interacting with TrustPoint as specified by R_005.

  Background:
    Given the server is running and reachable
    And I have a valid API key or token for authentication
    And the TrustPoint database contains existing resources for testing

  @rest_api @get @success
  Scenario Outline: Retrieve a resource using GET
    Given I have a valid endpoint <endpoint>
    When I send a GET request to <endpoint>
    Then the server should return a status code of 200
    And the response should include the requested resource details
    Examples:
      | endpoint            |
      | /identities         |
      | /certificates       |
      | /certificates/{id}  |

  @rest_api @get @failure
  Scenario Outline: Retrieve a non-existent resource using GET
    Given I have an invalid endpoint <endpoint>
    When I send a GET request to <endpoint>
    Then the server should return a status code of 404
    And the response should indicate <error_reason>
    Examples:
      | endpoint             | error_reason         |
      | /certificates/9999   | resource_not_found   |
      | /invalid_endpoint    | endpoint_not_found   |

  @rest_api @post @success
  Scenario Outline: Create a resource using POST
    Given I have a valid endpoint <endpoint>
    And I have a valid payload <payload>
    When I send a POST request to <endpoint> with the payload
    Then the server should return a status code of 201
    And the response should include the created resource details
    Examples:
      | endpoint       | payload                        |
      | /identities    | { "name": "Admin", "role": "Admin" } |
      | /certificates  | { "type": "TLS", "validity": "365" } |

  @rest_api @post @failure
  Scenario Outline: Create a resource with invalid data
    Given I have a valid endpoint <endpoint>
    And I have an invalid payload <payload>
    When I send a POST request to <endpoint> with the payload
    Then the server should return a status code of 400
    And the response should indicate <error_reason>
    Examples:
      | endpoint       | payload                   | error_reason         |
      | /identities    | { "name": "" }            | invalid_data         |
      | /certificates  | { "type": "", "validity": "365" } | missing_fields |

  @rest_api @put @success
  Scenario Outline: Update a resource using PUT
    Given I have a valid endpoint <endpoint>
    And I have a valid payload <payload>
    When I send a PUT request to <endpoint> with the payload
    Then the server should return a status code of 200
    And the response should include the updated resource details
    Examples:
      | endpoint              | payload                                |
      | /certificates/{id}    | { "type": "TLS", "validity": "730" }  |
      | /identities/{id}      | { "name": "Admin Updated", "role": "User" } |

  @rest_api @put @failure
  Scenario Outline: Update a resource with invalid data
    Given I have a valid endpoint <endpoint>
    And I have an invalid payload <payload>
    When I send a PUT request to <endpoint> with the payload
    Then the server should return a status code of 400
    And the response should indicate <error_reason>
    Examples:
      | endpoint              | payload                      | error_reason        |
      | /certificates/{id}    | { "validity": "" }           | invalid_field       |
      | /identities/{id}      | { "role": "InvalidRole" }    | invalid_role_value  |

  @rest_api @delete @success
  Scenario Outline: Delete a resource using DELETE
    Given I have a valid endpoint <endpoint>
    When I send a DELETE request to <endpoint>
    Then the server should return a status code of 204
    And the resource should no longer exist
    Examples:
      | endpoint              |
      | /certificates/{id}    |
      | /identities/{id}      |

  @rest_api @delete @failure
  Scenario Outline: Delete a non-existent resource using DELETE
    Given I have an invalid endpoint <endpoint>
    When I send a DELETE request to <endpoint>
    Then the server should return a status code of 404
    And the response should indicate <error_reason>
    Examples:
      | endpoint              | error_reason         |
      | /certificates/9999    | resource_not_found   |
      | /identities/invalid   | resource_not_found   |

  @rest_api @patch @success
  Scenario Outline: Partially update a resource using PATCH
    Given I have a valid endpoint <endpoint>
    And I have a valid partial payload <payload>
    When I send a PATCH request to <endpoint> with the payload
    Then the server should return a status code of 200
    And the response should include the updated resource details
    Examples:
      | endpoint              | payload                      |
      | /certificates/{id}    | { "validity": "180" }        |
      | /identities/{id}      | { "name": "User Updated" }   |
