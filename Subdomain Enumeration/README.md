# Project 5 – Subdomain Enumeration

## Overview
The Subdomain Enumeration prototype demonstrates how subdomains can be identified during an authorized security assessment. A domain may have multiple subdomains for different services, such as a customer portal, API, development environment, or administration interface.

> **Authorized-use requirement:** Enumerate only domains you own or have explicit permission to assess.

## Objectives
- Accept a target domain.
- Perform basic subdomain enumeration.
- Display discovered results.
- Handle invalid input and DNS errors.
- Document the enumeration process.
- Explain how the prototype works.

## Key Features
- Domain input
- Subdomain enumeration
- Result display
- Domain validation
- DNS resolution/error handling
- Clear documentation

## Suggested Technologies
- Python 3
- `socket` / DNS libraries
- Optional: a predefined wordlist
- Optional: DNS-over-HTTPS API in an authorized project

## How It Works
A basic wordlist-based prototype can combine candidate names with the target domain and attempt DNS resolution.

Example:

```text
Target Domain: example.com

Candidate
   ↓
api.example.com
   ↓
DNS Resolution
  ↙      ↘
Found   Not Found
  ↓         ↓
Result    Ignore
```

Possible candidates:

```text
www
mail
api
portal
admin
dev
test
```

## Example Output

```text
Target: example.com

Discovered Subdomains
---------------------
www.example.com
api.example.com
portal.example.com
```

The actual results depend on the authorized target and enumeration method.

## Error Handling
The application should handle:
- Invalid domain names
- Empty input
- DNS resolution failures
- Network timeouts
- API failures, if an external API is used
- Rate limits
- Duplicate results

## Security Concepts Demonstrated
- DNS
- Attack-surface discovery
- Security reconnaissance
- Domain/subdomain relationships
- Input validation
- Error handling
- Authorized security assessment

## Important Safety Note
Subdomain enumeration can reveal publicly accessible infrastructure. Only perform enumeration against domains you own or have explicit authorization to assess.

## Limitations
A wordlist-based method cannot guarantee discovery of every subdomain. Some subdomains may not resolve publicly, may be protected, or may use names not present in the wordlist.

## Future Enhancements
- Larger customizable wordlists
- DNS record inspection
- Certificate Transparency data for authorized assessments
- Result export to CSV/JSON
- Concurrency controls
- Duplicate removal
- Simple GUI

## Conclusion
This project demonstrates a basic approach to identifying subdomains as part of an authorized security-assessment workflow.
