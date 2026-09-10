# Project 2 – Network Security Port Scanner

## Overview
The Network Security Port Scanner is a basic educational tool that demonstrates how a security scanner can test a target host for TCP ports and identify whether selected ports are open or closed.

> **Authorized-use requirement:** Scan only systems you own or systems for which you have explicit permission to perform security testing.

## Objectives
- Accept a target IP address or hostname.
- Allow the user to select a port range.
- Perform basic TCP port scanning.
- Identify open and closed ports.
- Display clear scan results.
- Handle invalid input and connection errors.
- Document safe and authorized usage.

## Key Features
- Target input
- Start and end port selection
- TCP connection testing
- Open/closed port identification
- Scan progress/results
- Input validation
- Error handling
- Simple documentation

## Suggested Technologies
- Python 3
- `socket` library
- Optional: `argparse` for command-line arguments

## How It Works
For each port in the selected range, the scanner attempts a TCP connection to the target.

```text
Target + Port Range
        ↓
Validate Input
        ↓
For Each Port
        ↓
Attempt TCP Connection
      ↙     ↘
   Success   Failure
      ↓         ↓
    OPEN      CLOSED
        ↓
Display Results
```

## Example
For an authorized local lab target:

```text
Target: 127.0.0.1
Port Range: 1-100

Scan Results
------------
22   OPEN
80   OPEN
25   CLOSED
443  CLOSED
```

The exact results depend on the services running on the authorized target.

## Error Handling
The application should handle:
- Invalid IP/hostname
- Invalid port numbers
- Port ranges outside 1–65535
- Start port greater than end port
- Connection timeouts
- Network errors
- Unreachable targets

## Security Concepts Demonstrated
- TCP connections
- Port states
- Network service discovery
- Input validation
- Timeouts
- Error handling
- Security assessment workflow

## Important Safety Note
Port scanning can generate network traffic and may be considered suspicious or unauthorized on networks you do not control. Use the scanner only against your own computer, a private lab, or a system for which you have explicit authorization.

## Limitations
A basic TCP scanner does not provide complete network-security visibility. It may not identify UDP services, service versions, firewall behavior, or application-level vulnerabilities.

## Future Enhancements
- Multithreaded scanning
- Service/banner identification
- UDP scanning for an authorized lab
- Export results to CSV/JSON
- Scan timeout configuration
- Simple graphical interface

## Conclusion
This project demonstrates the fundamentals of TCP port scanning and how open services can be identified during an authorized security assessment.
