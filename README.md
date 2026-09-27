# APIGuard

## API Security Assessment & Vulnerability Analysis Platform

APIGuard is a Python and Flask-based API security assessment platform designed to discover API attack-surface issues, execute controlled security checks, generate explainable findings, map vulnerabilities to the OWASP API Security Top 10, and preserve assessment evidence.

The project uses a deliberately vulnerable enterprise-style AcmeCloud API as a controlled security testing laboratory.

## Key Capabilities

- API endpoint discovery and inventory validation
- Authentication security testing
- Object-level authorization testing
- Object property-level authorization testing
- Function-level authorization testing
- Sensitive business-flow testing
- SSRF detection
- Resource-consumption testing
- Security configuration checks
- OWASP API Security mapping
- Severity classification
- Evidence capture
- SQLite-based assessment history
- Flask-based security assessment dashboard
- Controlled before/after validation workflow

## Implemented OWASP API Security Coverage

| Category | Coverage |
|---|---|
| API1:2023  Broken Object Level Authorization | Implemented |
| API2:2023  Broken Authentication | Implemented |
| API3:2023  Broken Object Property Level Authorization | Implemented |
| API4:2023  Unrestricted Resource Consumption | Implemented |
| API5:2023  Broken Function Level Authorization | Implemented |
| API6:2023  Unrestricted Access to Sensitive Business Flows | Implemented |
| API7:2023  Server Side Request Forgery | Implemented |
| API8:2023  Security Misconfiguration | Implemented |
| API9:2023  Improper Inventory Management | Implemented |
| API10:2023  Unsafe Consumption of APIs | Planned |

## Technology Stack

- Python
- Flask
- SQLite
- REST APIs
- JWT
- Requests
- Pytest
- OWASP API Security Top 10
- CWE concepts
- HTML/CSS/JavaScript
- Git/GitHub
- Linux

## Architecture

```text
Target API
    |
    v
API Discovery
    |
    v
Authentication
    |
    v
Security Checks
    |
    +--> Authorization
    +--> Authentication
    +--> Business Flows
    +--> SSRF
    +--> Resource Consumption
    +--> Configuration
    +--> Inventory
    |
    v
Finding Engine
    |
    +--> OWASP Mapping
    +--> Severity
    +--> Evidence
    +--> Remediation
    |
    v
SQLite Database
    |
    v
Flask Security Dashboard
cd ~/APIGuard && cat > README.md <<'EOF'
# APIGuard

## API Security Assessment & Vulnerability Analysis Platform

APIGuard is a Python and Flask-based API security assessment platform designed to discover API attack-surface issues, execute controlled security checks, generate explainable findings, map vulnerabilities to the OWASP API Security Top 10, and preserve assessment evidence.

The project uses a deliberately vulnerable enterprise-style AcmeCloud API as a controlled security testing laboratory.

## Key Capabilities

- API endpoint discovery and inventory validation
- Authentication security testing
- Object-level authorization testing
- Object property-level authorization testing
- Function-level authorization testing
- Sensitive business-flow testing
- SSRF detection
- Resource-consumption testing
- Security configuration checks
- OWASP API Security mapping
- Severity classification
- Evidence capture
- SQLite-based assessment history
- Flask-based security assessment dashboard
- Controlled before/after validation workflow

## Implemented OWASP API Security Coverage

| Category | Coverage |
|---|---|
| API1:2023  Broken Object Level Authorization | Implemented |
| API2:2023  Broken Authentication | Implemented |
| API3:2023  Broken Object Property Level Authorization | Implemented |
| API4:2023  Unrestricted Resource Consumption | Implemented |
| API5:2023  Broken Function Level Authorization | Implemented |
| API6:2023  Unrestricted Access to Sensitive Business Flows | Implemented |
| API7:2023  Server Side Request Forgery | Implemented |
| API8:2023  Security Misconfiguration | Implemented |
| API9:2023  Improper Inventory Management | Implemented |
| API10:2023  Unsafe Consumption of APIs | Planned |

## Technology Stack

- Python
- Flask
- SQLite
- REST APIs
- JWT
- Requests
- Pytest
- OWASP API Security Top 10
- CWE concepts
- HTML/CSS/JavaScript
- Git/GitHub
- Linux

## Architecture

```text
Target API
    |
    v
API Discovery
    |
    v
Authentication
    |
    v
Security Checks
    |
    +--> Authorization
    +--> Authentication
    +--> Business Flows
    +--> SSRF
    +--> Resource Consumption
    +--> Configuration
    +--> Inventory
    |
    v
Finding Engine
    |
    +--> OWASP Mapping
    +--> Severity
    +--> Evidence
    +--> Remediation
    |
    v
SQLite Database
    |
    v
Flask Security DashboardControlled Security Laboratory

APIGuard includes a deliberately vulnerable AcmeCloud API used only for authorized local testing.

The lab contains:

JWT authentication
Customer and administrator roles
Customer profiles
Orders
Administrative functions
Internal diagnostic endpoints
Controlled vulnerability scenarios
API versioning
OpenAPI inventory
Security event and evidence tracking
Security Assessment Workflow
Discover
   
Authenticate
   
Establish API Surface
   
Execute Security Checks
   
Detect
   
Capture Evidence
   
Map to OWASP
   
Classify Severity
   
Recommend Remediation
   
Retest
Example Findings
APG-BOLA-001
API1:2023
High
GET /api/v1/orders/1003

APG-AUTH-001
API2:2023
High
POST /api/v1/auth/login

APG-FUNC-001
API5:2023
High
GET /api/v1/admin/users

APG-FLOW-001
API6:2023
High
POST /api/v1/orders/{order_id}/cancel

APG-SSRF-001
API7:2023
High
POST /api/v1/internal/fetch

APG-RESOURCE-001
API4:2023
Medium
GET /api/v1/orders

APG-CONFIG-001
API8:2023
Medium
GET /api/v1/health

APG-INVENTORY-001
API9:2023
Medium
GET /internal/debug
Testing

Run the automated test suite:

export PYTHONPATH="$PWD"
pytest -q

Current validation:

31 passed
0 failed
Safety

APIGuard is designed for authorized security testing in controlled environments.

The included vulnerable API is intentionally designed for local laboratory validation. Testing against systems without authorization is outside the intended scope of this project.

Project Status

Current implementation includes automated checks for eight OWASP API Security Top 10 categories.

API10 is intentionally listed as planned rather than claiming unsupported automated detection.

Author
Rutuja Bhosale
