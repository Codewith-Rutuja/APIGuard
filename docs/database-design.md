# APIGuard Database Design

## 1. Database Architecture

APIGuard separates the vulnerable target application's data from the security assessment platform's data.

### AcmeCloud Lab Database

Location:

`lab/acmecloud.db`

Purpose:

Stores the deliberately vulnerable AcmeCloud application's users, customers, orders, and audit events.

This database represents the target application being assessed.

### APIGuard Assessment Database

Location:

`data/apiguard.db`

Purpose:

Stores assessment targets, scans, discovered endpoints, security findings, evidence, and test execution history.

This separation prevents scanner data from being mixed with target application data.

---

# 2. AcmeCloud Lab Schema

## users

Stores authentication identities and authorization attributes.

| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| username | TEXT | Unique login username |
| password_hash | TEXT | Password hash |
| role | TEXT | customer, analyst, administrator |
| customer_id | INTEGER | Associated customer record |
| email | TEXT | User email |
| is_active | INTEGER | Account status |
| is_admin | INTEGER | Administrative privilege flag |
| created_at | TEXT | Account creation timestamp |

Security relevance:

- Authentication
- Role-based authorization
- Object ownership
- Property-level authorization
- Privilege escalation testing

---

## customers

Stores customer profile information.

| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| name | TEXT | Customer name |
| email | TEXT | Customer email |
| phone | TEXT | Customer phone |
| address | TEXT | Customer address |
| created_at | TEXT | Creation timestamp |

Security relevance:

- Sensitive data exposure
- Object-level authorization
- Property-level authorization

---

## orders

Stores customer order information.

| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| customer_id | INTEGER | Owner customer |
| order_number | TEXT | External order identifier |
| status | TEXT | Order status |
| amount | REAL | Order amount |
| description | TEXT | Order description |
| created_at | TEXT | Creation timestamp |

Security relevance:

- BOLA testing
- Object ownership validation
- Sensitive data exposure
- Authorization testing

---

## audit_events

Stores application security and activity events.

| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| actor_id | INTEGER | User performing action |
| action | TEXT | Performed operation |
| resource | TEXT | Affected resource |
| timestamp | TEXT | Event timestamp |
| correlation_id | TEXT | Request correlation identifier |

Security relevance:

- Incident investigation
- Security monitoring
- Auditability
- Request tracing

---

# 3. APIGuard Assessment Schema

## targets

Represents APIs authorized for assessment.

| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| name | TEXT | Target name |
| base_url | TEXT | API base URL |
| environment | TEXT | lab, development, staging |
| scope | TEXT | Authorized assessment scope |
| created_at | TEXT | Target creation timestamp |

---

## scans

Represents an individual security assessment execution.

| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| target_id | INTEGER | Associated target |
| status | TEXT | queued, running, completed, failed |
| started_at | TEXT | Scan start time |
| completed_at | TEXT | Scan completion time |
| scanner_version | TEXT | APIGuard version |

---

## endpoints

Stores the API attack-surface inventory discovered during assessment.

| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| scan_id | INTEGER | Associated scan |
| path | TEXT | API endpoint path |
| method | TEXT | HTTP method |
| source | TEXT | OpenAPI, crawler, manual |
| authenticated | INTEGER | Authentication requirement |
| discovered_at | TEXT | Discovery timestamp |

Security relevance:

- API inventory
- Attack-surface mapping
- Improper inventory management
- Endpoint coverage tracking

---

## findings

Stores detected security weaknesses.

| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| scan_id | INTEGER | Associated scan |
| endpoint_id | INTEGER | Affected endpoint |
| finding_key | TEXT | Stable finding identifier |
| title | TEXT | Finding title |
| description | TEXT | Finding description |
| severity | TEXT | Informational, Low, Medium, High, Critical |
| owasp_category | TEXT | OWASP API Security category |
| cwe | TEXT | CWE identifier |
| evidence | TEXT | Detection evidence |
| impact | TEXT | Security impact |
| remediation | TEXT | Recommended remediation |
| status | TEXT | Open, Resolved, Accepted |
| created_at | TEXT | Finding timestamp |

Design principle:

Every finding must be explainable and supported by evidence.

---

## evidence

Stores request and response evidence associated with a finding.

| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| finding_id | INTEGER | Associated finding |
| request_data | TEXT | Sanitized HTTP request |
| response_data | TEXT | Sanitized HTTP response |
| expected_behavior | TEXT | Expected security behavior |
| observed_behavior | TEXT | Observed behavior |
| captured_at | TEXT | Evidence timestamp |

Sensitive values such as passwords, tokens, cookies, and authorization headers must be redacted before storage.

---

## test_runs

Tracks individual security test execution.

| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| scan_id | INTEGER | Associated scan |
| test_case | TEXT | Test case identifier |
| endpoint_id | INTEGER | Tested endpoint |
| status | TEXT | Passed, Failed, Inconclusive |
| details | TEXT | Execution details |
| executed_at | TEXT | Execution timestamp |

---

# 4. Relationships

```text
TARGET
  |
   SCAN
       |
        ENDPOINT
       |     |
       |      FINDING
       |            |
       |             EVIDENCE
       |
        TEST_RUN
