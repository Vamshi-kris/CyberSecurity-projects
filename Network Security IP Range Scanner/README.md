# Project 3 – Network Security IP Range Scanner

## Overview
The IP Range Scanner is an educational network-discovery prototype that checks a specified IP range and identifies hosts that respond to a basic connectivity test.

> **Authorized-use requirement:** Use this scanner only on your own lab/network or an environment where you have explicit permission to perform discovery.

## Objectives
- Accept an IP address range.
- Discover responsive hosts.
- Identify active and inactive addresses.
- Display clear results.
- Validate IP/range input.
- Handle network and timeout errors.
- Explain the basic discovery process.

## Key Features
- IP range input
- Host discovery
- Active/inactive host identification
- Scan results
- Input validation
- Timeout handling
- Error handling
- Documentation

## Suggested Technologies
- Python 3
- `ipaddress` library
- `socket` and/or controlled ICMP/ping functionality

## How It Works
The application expands the supplied network/range into individual IP addresses and performs a basic connectivity check.

```text
IP Range Input
      ↓
Validate Network
      ↓
Generate IP Addresses
      ↓
Connectivity Check
    ↙       ↘
Response   No Response
   ↓           ↓
 ACTIVE      INACTIVE
      ↓
Display Results
```

## Example
For an authorized private lab network:

```text
Network: 192.168.1.0/29

Results
-----------------
192.168.1.1   ACTIVE
192.168.1.2   ACTIVE
192.168.1.3   INACTIVE
192.168.1.4   ACTIVE
192.168.1.5   INACTIVE
```

Results vary depending on the network and connectivity method.

## Error Handling
The scanner should handle:
- Invalid IP addresses
- Invalid CIDR ranges
- Incorrect range format
- Network timeouts
- Permission restrictions
- Unreachable hosts

## Security Concepts Demonstrated
- Network discovery
- IP addressing and CIDR
- Host availability
- Timeouts
- Input validation
- Safe network scanning practices

## Important Safety Note
Network discovery can reveal information about devices on a network. Do not scan networks you do not own or have permission to assess.

## Limitations
A host that does not respond to the chosen connectivity test is not necessarily inactive. Firewalls may block ICMP or other probes. Therefore, the prototype should treat results as connectivity observations rather than definitive proof that a device does or does not exist.

## Future Enhancements
- Parallel discovery with controlled concurrency
- Reverse DNS lookup
- MAC/vendor information in an authorized LAN
- CSV/JSON reporting
- Configurable timeouts
- Graphical interface

## Conclusion
This project demonstrates the basic process of discovering responsive hosts within an authorized IP range.
