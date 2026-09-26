# LAB-01  Broken Object Level Authorization

## Objective

Validate whether an authenticated customer can access another customer's
object by modifying the object identifier.

## Test Setup

- API: AcmeCloud API v1
- Attacker identity: Alice
- Attacker customer_id: 101
- Target object: Order 1003
- Target owner: Bob
- Target customer_id: 102

## Test

Alice authenticated successfully and requested:

GET /api/v1/orders/1003

The API returned order 1003 even though the authenticated user's
customer_id was 101 and the order belonged to customer_id 102.

## Result

VULNERABLE

## OWASP Mapping

API1:2023  Broken Object Level Authorization

## Security Principle Violated

Authentication confirms who the requester is, but authorization must also
verify whether that requester is permitted to access the requested object.

## Expected Secure Behavior

The API should deny Alice's request because order 1003 belongs to Bob.

The secure implementation should return an appropriate authorization
failure without exposing Bob's order data.

## Validation Plan

1. Detect the vulnerable behavior with APIGuard.
2. Capture request and response evidence.
3. Map the finding to OWASP API1:2023.
4. Classify severity.
5. Implement object-level authorization.
6. Repeat the same test.
7. Confirm that the finding is resolved.
