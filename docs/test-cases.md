# APIGuard  Security Test Cases

## Purpose

This document defines the initial security conditions that APIGuard will validate against the controlled vulnerable API laboratory.

The test cases are designed to produce observable evidence that can be mapped to OWASP API Security Top 10 2023 categories.

---

## TC-01  Broken Object Level Authorization

### Objective

Determine whether an authenticated user can access an object belonging to another user without the required authorization.

### Example

User A authenticates successfully.

User A requests:

    GET /api/users/102

The requested object belongs to User B.

### Expected secure behavior

The API denies access.

### Vulnerable behavior

The API returns User B's protected object.

### OWASP Mapping

API1  Broken Object Level Authorization

---

## TC-02  Broken Authentication

### Objective

Determine whether protected API resources can be accessed without valid authentication.

### Test

Send a request to a protected endpoint:

    GET /api/profile

without a valid authentication token.

### Expected secure behavior

The API returns an authentication error.

### Vulnerable behavior

The API returns protected data without valid authentication.

### OWASP Mapping

API2  Broken Authentication

---

## TC-03  Broken Object Property Level Authorization

### Objective

Determine whether a user can access or modify object properties that should not be exposed or controlled by that user.

### Example

A normal user attempts to modify a privileged property such as:

    is_admin

### Expected secure behavior

The server rejects unauthorized property modification.

### Vulnerable behavior

The server accepts the unauthorized property change.

### OWASP Mapping

API3  Broken Object Property Level Authorization

---

## TC-04  Unrestricted Resource Consumption

### Objective

Determine whether an endpoint permits excessive requests or resource-intensive input without effective controls.

### Test

Perform a controlled sequence of requests against the local laboratory API.

### Expected secure behavior

The API applies appropriate request or resource controls.

### Vulnerable behavior

The API permits excessive controlled requests without an effective protective mechanism.

### OWASP Mapping

API4  Unrestricted Resource Consumption

---

## TC-05  Broken Function Level Authorization

### Objective

Determine whether a lower-privileged user can invoke functionality reserved for a higher-privileged role.

### Example

A normal user attempts to access:

    POST /api/admin/users

### Expected secure behavior

The API denies the operation.

### Vulnerable behavior

The normal user successfully invokes the privileged function.

### OWASP Mapping

API5  Broken Function Level Authorization

---

## TC-06  JWT Security Validation

### Objective

Evaluate whether JWT authentication controls are implemented correctly.

### Checks

- Token presence
- Token signature validation
- Token expiration validation
- Required claims
- Algorithm handling
- Invalid token rejection

### Expected secure behavior

Invalid or unacceptable tokens are rejected.

### OWASP Mapping

API2  Broken Authentication

---

## TC-07  Security Misconfiguration

### Objective

Identify observable insecure API configuration conditions.

### Initial checks

- Debug information exposure
- Excessive server information
- Missing security headers where applicable
- Unsafe CORS configuration
- Verbose error responses
- Insecure transport configuration where observable

### OWASP Mapping

API8  Security Misconfiguration

---

## TC-08  Improper API Inventory

### Objective

Identify inconsistencies between documented and observed API endpoints.

### Initial source

OpenAPI specification.

### Checks

- Documented endpoints
- HTTP methods
- Authentication requirements
- Endpoint inventory consistency

### OWASP Mapping

API9  Improper Inventory Management

---

## Evidence Requirements

Every confirmed finding should retain enough evidence to explain the detection.

Evidence should include, where appropriate:

- Endpoint
- HTTP method
- Request characteristics
- Response status
- Relevant response data
- Detection condition
- Timestamp

Sensitive credentials and secrets must be redacted.

---

## Validation Requirement

Every detection must be validated using the controlled vulnerable API laboratory.

The validation sequence is:

1. Create vulnerable condition
2. Run APIGuard assessment
3. Detect condition
4. Record evidence
5. Map to OWASP
6. Apply remediation
7. Run assessment again
8. Confirm the finding is resolved

---

## Scope

Testing is limited to APIs owned by the tester or explicitly authorized for security assessment.

The included vulnerable API laboratory is intentionally insecure and exists only for controlled testing.
