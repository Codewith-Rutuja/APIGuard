# APIGuard  Security Assessment Methodology

## 1. Purpose

This document defines the methodology used by APIGuard to assess APIs for security weaknesses.

The methodology emphasizes controlled testing, observable evidence, repeatability, and explainable findings.

---

## 2. Assessment Lifecycle

APIGuard follows the following assessment lifecycle:

1. Define target and scope
2. Discover API endpoints
3. Build endpoint inventory
4. Establish baseline behavior
5. Execute security test
6. Analyze response
7. Determine whether a security condition exists
8. Collect evidence
9. Map the condition to OWASP
10. Classify severity
11. Provide remediation guidance
12. Generate assessment results

---

## 3. Scope Validation

Before active testing begins, APIGuard requires a defined target and assessment scope.

The target must be an API that the tester owns or is explicitly authorized to assess.

Testing outside the defined scope is not part of the APIGuard workflow.

---

## 4. API Discovery

APIGuard initially supports API discovery through OpenAPI specifications.

The discovery process extracts:

- Endpoint paths
- HTTP methods
- Parameters
- Request bodies
- Response definitions
- Authentication requirements
- API documentation metadata

The discovered information becomes the initial endpoint inventory.

---

## 5. Baseline Establishment

Before security testing, APIGuard establishes normal API behavior where possible.

Baseline information may include:

- HTTP status code
- Response structure
- Response headers
- Response body characteristics
- Authentication requirements
- Expected authorization behavior

The baseline is used to distinguish expected behavior from suspicious behavior.

---

## 6. Security Test Execution

Security tests are executed against the controlled target according to the defined test case.

Examples include:

- Unauthenticated request testing
- Authenticated authorization testing
- Object access comparison
- Role-based access testing
- Property modification testing
- JWT validation testing
- Configuration analysis
- Controlled rate/resource testing
- API inventory comparison

Tests should use the minimum activity necessary to establish the security condition.

---

## 7. Detection Logic

A potential finding must be supported by an observable security condition.

APIGuard should not classify a vulnerability based only on a single generic indicator such as an HTTP 200 response.

Detection logic should consider relevant context including:

- Request identity
- Authentication state
- Authorization context
- HTTP method
- Endpoint
- Response status
- Response content
- Expected behavior
- Test condition
- Baseline behavior

Where possible, detection should compare a controlled test result against an expected secure result.

---

## 8. Evidence Collection

When a security condition is detected, APIGuard records supporting evidence.

Evidence may include:

- Endpoint
- HTTP method
- Request metadata
- Response status
- Relevant response fields
- Test condition
- Detection explanation
- Timestamp

Secrets, credentials, session tokens, and other sensitive information must be redacted.

---

## 9. False Positive Reduction

APIGuard should prioritize evidence quality over the number of reported findings.

Before creating a confirmed finding, the detection engine should verify that the observed behavior matches the conditions defined by the relevant test case.

Where automated validation cannot establish sufficient confidence, the result should be represented as a potential finding or informational observation rather than an automatically confirmed vulnerability.

---

## 10. OWASP Mapping

Confirmed findings are mapped to the applicable OWASP API Security Top 10 2023 category.

A finding should only be mapped when the observed condition is relevant to the category.

The OWASP mapping provides classification context and does not replace technical evidence.

---

## 11. Severity Classification

APIGuard uses the following severity levels:

- Informational
- Low
- Medium
- High
- Critical

Severity is determined using documented criteria based on factors such as:

- Exploitability
- Authentication requirements
- Authorization requirements
- Data exposure
- Security impact
- Potential business impact
- Scope of affected resources

Severity must be assigned consistently using the project's defined rules.

---

## 12. Remediation

Each confirmed finding should provide practical remediation guidance.

Remediation should address the underlying security control rather than only the observed symptom.

Examples:

- Enforce server-side object authorization
- Validate authentication tokens
- Enforce role-based access controls
- Restrict writable object properties
- Apply request and resource limits
- Disable unsafe configuration
- Maintain accurate API inventories

---

## 13. Validation and Retesting

Every major detection capability must be validated using the controlled vulnerable API laboratory.

The validation process is:

1. Configure vulnerable condition
2. Confirm vulnerable behavior manually
3. Run APIGuard
4. Verify detection
5. Verify evidence
6. Verify OWASP mapping
7. Apply remediation
8. Rerun APIGuard
9. Confirm the finding is no longer detected

This process demonstrates that the detection logic identifies a real security condition rather than producing an arbitrary alert.

---

## 14. Assessment Output

A completed assessment should provide:

- Target information
- Assessment scope
- API inventory
- Tests performed
- Findings
- Severity
- OWASP classification
- Evidence
- Impact
- Remediation
- Retest status

---

## 15. Safety Principle

APIGuard is intended for authorized security assessment.

The project laboratory is intentionally vulnerable and exists to validate detection logic in a controlled environment.

The tool must not be presented as a license to test systems without authorization.
