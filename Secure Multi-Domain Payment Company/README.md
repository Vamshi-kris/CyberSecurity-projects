# Project 6 – Secure Multi-Domain Payment Company

## Overview
This project demonstrates a secure architecture for a fictional payment company that operates multiple applications and backend services. The objective is to show how security controls can be applied across different domains/applications rather than building a real payment gateway.

The prototype may contain:
- Main website
- Customer portal
- Payment application
- Admin portal
- APIs/backend services

> **Important:** This is an educational security-architecture prototype. It does not process real payments or replace a production payment platform.

## Objectives
- Demonstrate secure authentication.
- Implement authorization and access control.
- Demonstrate secure password handling.
- Use secure communication principles.
- Validate application inputs.
- Protect APIs.
- Manage user sessions securely.
- Demonstrate security logging and monitoring.
- Separate applications/domains.
- Apply basic payment-security principles.

## Suggested Architecture

```text
                    ┌─────────────────┐
                    │   Main Website  │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              ↓                             ↓
     ┌─────────────────┐           ┌─────────────────┐
     │ Customer Portal │           │   Admin Portal  │
     └────────┬────────┘           └────────┬────────┘
              │                             │
              └──────────────┬──────────────┘
                             ↓
                    ┌─────────────────┐
                    │ API / Backend   │
                    └────────┬────────┘
                             ↓
                    ┌─────────────────┐
                    │ Payment Service │
                    └────────┬────────┘
                             ↓
                    ┌─────────────────┐
                    │    Database     │
                    └─────────────────┘
```

## Domain/Application Separation
A conceptual deployment could use separate hosts such as:

```text
www.company.test       → Main website
customer.company.test  → Customer portal
pay.company.test       → Payment application
admin.company.test     → Admin portal
api.company.test       → Backend API
```

These are example names for a local/demo environment.

## Core Security Controls

### 1. Secure Authentication
- Registration and login
- Secure password hashing
- Session/token management
- Optional MFA concept
- Login rate limiting

### 2. Authorization
Use role-based access control.

Example roles:

| Role | Customer Portal | Payment Functions | Admin Portal |
|---|---|---|---|
| Customer | Yes | Own transactions | No |
| Support | Limited | Limited | Limited |
| Admin | Yes | Authorized operations | Yes |

Users should only access resources permitted for their role.

### 3. Password Security
- Hash passwords with Argon2id or bcrypt.
- Never store plaintext passwords.
- Never log passwords.
- Apply reasonable password policies.
- Protect password-reset functionality.

### 4. Secure Communication
Use HTTPS/TLS for real deployments.

```text
Client
  ↓ HTTPS/TLS
Application
  ↓ Secure internal connection
API
  ↓ Secure service connection
Payment Service
```

### 5. Input Validation
Validate:
- Amounts
- Account identifiers
- User information
- API parameters
- Request formats

Reject unexpected or malformed data before business processing.

### 6. API Security
- Authenticate API requests.
- Authorize each sensitive operation.
- Validate request schemas.
- Apply rate limits.
- Avoid exposing sensitive information in responses.
- Use appropriate API keys/tokens where applicable.
- Log important security events.

### 7. Session Management
- Use secure session identifiers.
- Use Secure and HttpOnly cookie attributes for browser sessions.
- Apply SameSite controls where appropriate.
- Expire inactive sessions.
- Invalidate sessions during logout.

### 8. Logging and Monitoring
Security-relevant events can include:
- Successful login
- Failed login
- Logout
- Authorization failure
- Sensitive administrative operation
- Suspicious request patterns
- Payment-operation events

Do not log passwords, authentication tokens, or unnecessary payment-sensitive information.

## Basic Payment-Security Considerations
A real payment system requires substantially more controls. This prototype should demonstrate concepts such as:
- Least privilege
- Data minimization
- Encryption in transit
- Secure secrets management
- Transaction authorization
- Audit logging
- Fraud/risk-control concepts
- Separation of sensitive services

Do not use real card numbers or real payment credentials in the prototype.

## Example Payment Flow

```text
Customer Login
      ↓
Authentication
      ↓
Customer Authorization
      ↓
Enter Payment Information
      ↓
Input Validation
      ↓
Create Payment Request
      ↓
Authenticated API
      ↓
Payment Service
      ↓
Demo Transaction Result
      ↓
Audit Log
      ↓
Customer Response
```

## Suggested Technologies
- Frontend: HTML/CSS/JavaScript or React
- Backend: Flask/FastAPI, Node.js/Express, Spring Boot, etc.
- Database: PostgreSQL/MySQL/SQLite for demonstration
- API: REST
- Authentication: Session-based authentication or secure tokens
- Deployment: Docker/local development environment

## Security Testing Checklist
- [ ] Authentication required for protected pages
- [ ] Authorization checked on every sensitive operation
- [ ] Passwords stored only as secure hashes
- [ ] Input validation implemented server-side
- [ ] Sessions protected
- [ ] HTTPS/TLS planned or enabled in deployment
- [ ] API requests authenticated and authorized
- [ ] Security events logged
- [ ] Secrets kept outside source code
- [ ] No real payment credentials used
- [ ] Admin functionality isolated from normal users

## Limitations
This project is a prototype for demonstrating cybersecurity architecture. It is not a production payment gateway and should not process real financial transactions or sensitive customer payment data.

## Future Enhancements
- MFA
- Centralized identity provider
- API gateway
- Web Application Firewall
- Secrets manager
- Centralized security monitoring/SIEM
- Database encryption
- Transaction risk engine
- Automated security testing
- Container and infrastructure security
- Compliance-oriented controls

## Conclusion
The project demonstrates how a multi-application payment company can apply defense-in-depth principles by separating applications, enforcing authentication and authorization, securing APIs and sessions, validating input, protecting sensitive data, and monitoring security-relevant activity.
