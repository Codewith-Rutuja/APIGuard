# APIGuard  System Architecture

## 1. Purpose

APIGuard is a controlled API security assessment platform designed to identify and document security weaknesses in APIs that the tester owns or is explicitly authorized to assess.

The platform performs API discovery, security testing, vulnerability detection, evidence collection, OWASP API Security mapping, risk classification, and remediation reporting.

## 2. Core Workflow

Authorized API
    
API Discovery
    
Endpoint Inventory
    
Security Testing
    
Detection Engine
    
OWASP Mapping
    
Risk Classification
    
Evidence Collection
    
Remediation Guidance
    
Security Assessment Report

## 3. Major Components

### 3.1 Target and Scope

Defines the API target, allowed scope, authentication configuration, and assessment settings.

### 3.2 API Discovery

Identifies API endpoints, HTTP methods, parameters, authentication requirements, and available API documentation.

Primary supported discovery source:
- OpenAPI specification

Future controlled discovery may support manually supplied endpoints.

### 3.3 Security Testing Engine

Performs controlled security checks against the authorized API.

Initial testing areas:

- Authentication
- Authorization
- Object-level authorization
- Function-level authorization
- Property-level authorization
- JWT security
- Input validation
- Security configuration
- Rate limiting and resource consumption
- API inventory

### 3.4 Detection Engine

Analyzes HTTP requests and responses to determine whether a security condition indicates a potential vulnerability.

Every finding must have:

- Finding ID
- Title
- Description
- Endpoint
- HTTP method
- Evidence
- Security impact
- OWASP category
- Severity
- Remediation guidance

### 3.5 OWASP Mapping

Findings are mapped to the OWASP API Security Top 10 2023 categories where applicable.

### 3.6 Risk Classification

APIGuard assigns severity based on the observed security condition and its potential impact.

Severity levels:

- Informational
- Low
- Medium
- High
- Critical

The severity model will be documented and implemented consistently rather than assigned arbitrarily.

### 3.7 Evidence Collection

The platform stores relevant request and response evidence needed to support a finding.

Sensitive information must be redacted before evidence is displayed or included in reports.

### 3.8 Dashboard

The dashboard provides:

- Assessment overview
- Endpoint inventory
- Findings
- Severity distribution
- OWASP category distribution
- Finding details
- Evidence
- Remediation guidance

### 3.9 Reporting

The reporting component generates a professional security assessment report containing:

- Executive summary
- Assessment scope
- Methodology
- API inventory
- Findings
- Evidence
- Risk classification
- OWASP mapping
- Remediation recommendations

## 4. Controlled Testing Principle

APIGuard is intended for APIs that the tester owns or is explicitly authorized to assess.

The project will include a deliberately vulnerable local API laboratory for validating detection logic.

Testing against third-party systems without authorization is outside the project scope.

## 5. Validation Method

Every major detection capability should be validated using:

1. A deliberately vulnerable API condition
2. An APIGuard assessment
3. Detection of the condition
4. Evidence capture
5. OWASP classification
6. Remediation
7. Reassessment
8. Confirmation that the finding is resolved

## 6. Design Principle

APIGuard should prioritize explainable security findings over the number of detected vulnerabilities.

A finding is considered useful only when the platform can explain:

- What was tested
- Why it was tested
- What was observed
- Why the observation indicates a security weakness
- What the potential impact is
- How the issue can be remediated
