# BOLA Detection Methodology

## Objective

Detect Broken Object Level Authorization (BOLA) in APIs where an authenticated user can access an object belonging to another user.

## OWASP Mapping

- OWASP API1:2023  Broken Object Level Authorization
- CWE-639  Authorization Bypass Through User-Controlled Key

## Controlled Test

APIGuard authenticates as the Alice customer account and requests:

`GET /api/v1/orders/1003`

Order `1003` belongs to Bob.

The detector compares:

- authenticated customer identity
- customer identity returned in the object response

## Detection Logic

A finding is generated when:

1. Authentication succeeds.
2. The requested object exists.
3. The API returns HTTP 200.
4. The response contains a valid object owner identifier.
5. The returned owner differs from the authenticated customer.

## False-Positive Control

APIGuard also tests an object belonging to the authenticated customer.

For example:

`GET /api/v1/orders/1001`

Order `1001` belongs to Alice.

This request must not generate a finding.

## Evidence

Each detected finding records:

- Endpoint
- HTTP method
- Requested object identifier
- Authenticated customer identifier
- Returned object owner identifier
- OWASP category
- Severity
- Impact
- Remediation

## Expected Secure Behavior

The API should prevent a customer from retrieving another customer's object.

A secure implementation should return an authorization failure rather than the protected object.

## Validation Cycle

The vulnerability is validated using:

`Detect  Capture Evidence  Fix  Retest`

A successful retest should produce no BOLA finding for the previously vulnerable request.
