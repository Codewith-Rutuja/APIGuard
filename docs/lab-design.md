# APIGuard  Controlled API Security Laboratory Design

## 1. Laboratory Purpose

The APIGuard laboratory is a deliberately vulnerable, local REST API environment used to validate the security assessment capabilities of APIGuard.

The laboratory represents a fictional enterprise platform named AcmeCloud.

The environment is intentionally designed with realistic application architecture, authentication, authorization, business objects, administrative functions, API documentation, audit events, and security controls.

All security testing is performed against this local laboratory.

---

# 2. AcmeCloud API

AcmeCloud is a fictional cloud-based customer and order management platform.

The API provides:

- Identity and authentication
- Customer profiles
- Orders
- Administrative operations
- Audit information
- API health information

Initial API version:

    /api/v1/

The API uses JSON request and response bodies.

---

# 3. User Roles

## 3.1 Customer

Normal application user.

Capabilities:

- Authenticate
- View own profile
- Update permitted profile information
- View own orders
- View permitted order information

Restrictions:

- Cannot access another customer's resources
- Cannot perform administrative operations
- Cannot modify privileged account properties

---

## 3.2 Analyst

Security or support-oriented application role.

Capabilities:

- View customer records required for support operations
- View order information
- View selected audit information

Restrictions:

- Cannot perform administrative account-management operations
- Cannot modify privileged account properties

---

## 3.3 Administrator

Privileged application role.

Capabilities:

- Manage users
- View administrative information
- Perform privileged account operations
- Access administrative endpoints

---

# 4. Test Identities

The laboratory will contain controlled test identities.

## Administrator

Username:

    admin

Role:

    administrator

---

## Analyst

Username:

    analyst

Role:

    analyst

---

## Customer Alice

Username:

    alice

Role:

    customer

Customer ID:

    101

---

## Customer Bob

Username:

    bob

Role:

    customer

Customer ID:

    102

---

# 5. Authentication Model

AcmeCloud uses JWT bearer authentication.

Authentication flow:

    POST /api/v1/auth/login
                |
                v
        Credential validation
                |
                v
            JWT issued
                |
                v
    Authorization: Bearer <token>

The JWT contains application identity information required for authorization.

Example conceptual claims:

- sub
- username
- role
- customer_id
- iat
- exp

The implementation must validate tokens server-side.

---

# 6. Security Context

For each authenticated request, the application should establish:

- User identity
- User role
- Customer identity where applicable
- Token validity
- Authorization context

Authorization decisions must be performed server-side.

Client-supplied identity or ownership values must not be trusted without verification.

---

# 7. Core Data Model

## User

Fields:

- id
- username
- password_hash
- role
- customer_id
- email
- is_active
- is_admin
- created_at

The is_admin field represents a privileged security property.

Normal users must not be able to modify this property.

---

## Customer

Fields:

- id
- name
- email
- phone
- address
- created_at

Customer records contain information that should only be accessible according to authorization rules.

---

## Order

Fields:

- id
- customer_id
- order_number
- status
- amount
- description
- created_at

Orders are owned by customers.

Object-level authorization must verify that the requesting identity is permitted to access the requested order.

---

## Audit Event

Fields:

- id
- actor_id
- action
- resource
- timestamp
- correlation_id

Audit events provide security-relevant context for application activity.

---

# 8. API Endpoint Inventory

## Authentication

POST

    /api/v1/auth/login

Purpose:

Authenticate a user and issue a JWT.

---

## Profile

GET

    /api/v1/profile

Purpose:

Return the authenticated user's profile.

Authentication:

Required.

---

PUT

    /api/v1/profile

Purpose:

Update permitted profile fields.

Authentication:

Required.

---

## User Objects

GET

    /api/v1/users/{user_id}

Purpose:

Retrieve a user record.

Authentication:

Required.

Authorization:

Object access must be enforced.

---

PUT

    /api/v1/users/{user_id}

Purpose:

Update permitted user properties.

Authentication:

Required.

Authorization:

Object and property-level authorization required.

---

## Orders

GET

    /api/v1/orders/{order_id}

Purpose:

Retrieve an order.

Authentication:

Required.

Authorization:

The requesting identity must be permitted to access the order.

---

## Administrative Operations

GET

    /api/v1/admin/users

Purpose:

List application users.

Authentication:

Required.

Authorization:

Administrator role required.

---

POST

    /api/v1/admin/users

Purpose:

Create an application user.

Authentication:

Required.

Authorization:

Administrator role required.

---

DELETE

    /api/v1/admin/users/{user_id}

Purpose:

Delete an application user.

Authentication:

Required.

Authorization:

Administrator role required.

---

## Audit

GET

    /api/v1/audit/events

Purpose:

Return security-relevant audit events.

Authentication:

Required.

Authorization:

Restricted according to role.

---

## Health

GET

    /api/v1/health

Purpose:

Return service health information.

Authentication:

Not required.

---

# 9. Deliberately Vulnerable Conditions

The vulnerable laboratory version will contain controlled security weaknesses.

Each weakness must be realistic enough to demonstrate an actual security control failure.

---

## LAB-01  Broken Object Level Authorization

Condition:

A customer can request another customer's object by changing the object identifier.

Example:

Alice authenticates.

Alice requests:

    GET /api/v1/orders/5002

Order 5002 belongs to Bob.

Vulnerable behavior:

The API returns Bob's order.

Secure behavior:

The API denies access.

OWASP:

API1  Broken Object Level Authorization

---

# 10. LAB-02  Broken Authentication

Condition:

A protected endpoint contains an authentication enforcement weakness.

Example:

    GET /api/v1/profile

Vulnerable behavior:

Protected information is returned without valid authentication.

Secure behavior:

The API returns an authentication error.

OWASP:

API2  Broken Authentication

---

# 11. LAB-03  Broken Object Property Level Authorization

Condition:

A normal customer can modify a property that should only be controlled by privileged application logic.

Example request:

    PUT /api/v1/users/101

Request body includes:

    is_admin: true

Vulnerable behavior:

The privileged property is accepted.

Secure behavior:

The property is rejected or ignored according to the application's authorization model.

OWASP:

API3  Broken Object Property Level Authorization

---

# 12. LAB-04  Unrestricted Resource Consumption

Condition:

A controlled endpoint does not apply an appropriate request/resource limit.

The laboratory will provide a bounded testing mechanism.

APIGuard must avoid uncontrolled request flooding.

The assessment will use a small, predefined request sequence.

OWASP:

API4  Unrestricted Resource Consumption

---

# 13. LAB-05  Broken Function Level Authorization

Condition:

A lower-privileged user can invoke an administrator-only function.

Example:

Alice attempts:

    POST /api/v1/admin/users

Vulnerable behavior:

The operation succeeds.

Secure behavior:

The server returns an authorization error.

OWASP:

API5  Broken Function Level Authorization

---

# 14. LAB-06  JWT Security Validation

The laboratory will contain controlled JWT validation conditions for testing.

APIGuard will evaluate:

- Missing token
- Invalid token
- Expired token
- Invalid signature
- Required claims
- Algorithm handling

Secure behavior:

Unacceptable tokens are rejected.

OWASP:

API2  Broken Authentication

---

# 15. LAB-07  Security Misconfiguration

The laboratory will intentionally expose selected configuration weaknesses.

Examples may include:

- Verbose error information
- Excessive server information
- Unsafe CORS configuration
- Missing security headers
- Debug-related information

The conditions will be observable through API behavior or HTTP responses.

OWASP:

API8  Security Misconfiguration

---

# 16. LAB-08  Improper API Inventory

The laboratory will contain a controlled discrepancy between the documented API inventory and the implemented API surface.

Example:

An endpoint exists in the running application but is absent from the OpenAPI documentation.

APIGuard should identify the inventory inconsistency.

OWASP:

API9  Improper Inventory Management

---

# 17. Secure Version

The laboratory must eventually have a secure implementation of each vulnerable condition.

The secure version will enforce:

- Authentication
- Object authorization
- Function authorization
- Property authorization
- JWT validation
- Resource controls
- Secure configuration
- Accurate API inventory

This allows APIGuard findings to be validated through before-and-after testing.

---

# 18. Validation Model

For every vulnerability:

    Vulnerable implementation
            |
            v
    Manual confirmation
            |
            v
       APIGuard scan
            |
            v
       Finding created
            |
            v
      Evidence captured
            |
            v
       OWASP mapped
            |
            v
      Remediation applied
            |
            v
        Secure version
            |
            v
       APIGuard rescan
            |
            v
      Finding resolved

---

# 19. API Response Standards

The laboratory API should use structured JSON responses.

Successful response example:

    {
        "success": true,
        "data": {}
    }

Error response example:

    {
        "success": false,
        "error": {
            "code": "AUTHORIZATION_FAILED",
            "message": "Access denied"
        }
    }

Responses should contain enough information for APIGuard to analyze behavior without unnecessarily exposing sensitive information.

---

# 20. Request Correlation

API requests should support a correlation identifier.

Example:

    X-Correlation-ID

The identifier can be used to connect:

- API requests
- Application logs
- Audit events
- APIGuard evidence

This provides realistic security investigation context.

---

# 21. Audit Logging

Security-relevant operations should generate audit events.

Examples:

- Login
- Failed login
- Profile update
- Order access
- Administrative operation
- Authorization failure

Audit information will help demonstrate how API security testing can connect with security monitoring concepts.

---

# 22. OpenAPI Documentation

The laboratory will provide an OpenAPI specification describing the intended API surface.

The specification will be used by APIGuard for API discovery and inventory creation.

The inventory comparison capability will compare documented API information with observed API behavior.

---

# 23. Design Principle

The laboratory should resemble a small real-world application rather than a collection of artificial vulnerability endpoints.

Security weaknesses should represent realistic implementation or configuration failures.

The goal is to allow APIGuard to demonstrate:

- API discovery
- Authentication analysis
- Authorization testing
- Behavioral analysis
- Evidence collection
- Vulnerability classification
- Risk assessment
- Remediation
- Retesting

---

# 24. Safety Boundary

The laboratory is local and intentionally vulnerable.

All active security testing performed during development must remain within the controlled laboratory or another explicitly authorized target.

APIGuard is a security assessment platform, not a tool for testing systems without authorization.

