#!/usr/bin/env python3
"""
IP Range Scanner - Network Discovery Tool
Demonstrates network host discovery using concurrent ICMP and socket probing.
"""

import argparse
import concurrent.futures
import ipaddress
import platform
import socket
import subprocess
import sys
import time
from typing import List, Tuple, Optional

# Default configuration
DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 1.0  # seconds
PROBE_PORTS = [80, 443, 22, 445, 135]


def parse_ip_targets(target_input: str) -> List[ipaddress.IPv4Address]:
    """
    Parses CIDR notation (192.168.1.0/24) or hyphenated ranges (192.168.1.1-192.168.1.30).
    """
    targets = []
    target_input = target_input.strip()

    try:
        # Case 1: Hyphenated range (e.g., 192.168.1.5-192.168.1.25)
        if '-' in target_input:
            parts = target_input.split('-')
            if len(parts) != 2:
                raise ValueError("Invalid range format. Use StartIP-EndIP.")
            
            start_str, end_str = parts[0].strip(), parts[1].strip()
            start_ip = ipaddress.IPv4Address(start_str)
            
            # Allow short format (192.168.1.1-50) or full IP (192.168.1.1-192.168.1.50)
            if '.' not in end_str:
                network_prefix = str(start_ip).rsplit('.', 1)[0]
                end_ip = ipaddress.IPv4Address(f"{network_prefix}.{end_str}")
            else:
                end_ip = ipaddress.IPv4Address(end_str)

            if int(start_ip) > int(end_ip):
                raise ValueError("Start IP must be less than or equal to End IP.")

            curr = int(start_ip)
            while curr <= int(end_ip):
                targets.append(ipaddress.IPv4Address(curr))
                curr += 1

        # Case 2: CIDR notation or single host
        else:
            net = ipaddress.ip_network(target_input, strict=False)
            # If network has host addresses (e.g., /24), scan hosts; if /32, scan that host
            if net.num_addresses > 1:
                targets = list(net.hosts())
            else:
                targets = [net.network_address]

    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
        raise ValueError(f"IP Input Error: {str(e)}")

    return targets


def icmp_ping(ip: str, timeout: float) -> bool:
    """
    Executes a platform-appropriate ICMP echo request.
    """
    param_count = "-n" if platform.system().lower() == "windows" else "-c"
    param_timeout = "-w" if platform.system().lower() == "windows" else "-W"
    
    # Windows timeout is in milliseconds; Unix is in seconds
    timeout_val = str(int(timeout * 1000)) if platform.system().lower() == "windows" else str(int(max(1, timeout)))
    
    cmd = ["ping", param_count, "1", param_timeout, timeout_val, ip]
    
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def tcp_fallback_check(ip: str, ports: List[int], timeout: float) -> Tuple[bool, Optional[int]]:
    """
    Probes standard TCP ports to detect active hosts blocking ICMP.
    """
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                sock.close()
                return True, port
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
    return False, None


def probe_host(ip_obj: ipaddress.IPv4Address, timeout: float) -> dict:
    """
    Evaluates host status using ICMP first, falling back to TCP connect scan.
    """
    ip_str = str(ip_obj)
    
    # Step 1: Ping
    if icmp_ping(ip_str, timeout):
        return {"ip": ip_str, "status": "Active", "method": "ICMP Ping", "detail": "Echo Reply"}
    
    # Step 2: TCP Syn/Connect Probe fallback
    is_open, port = tcp_fallback_check(ip_str, PROBE_PORTS, timeout)
    if is_open:
        return {"ip": ip_str, "status": "Active", "method": "TCP Probe", "detail": f"Port {port} Open"}
    
    return {"ip": ip_str, "status": "Inactive", "method": "None", "detail": "No response"}


def run_scanner(targets: List[ipaddress.IPv4Address], max_workers: int, timeout: float):
    """
    Manages concurrent thread pool execution and reports live results.
    """
    print(f"\n[+] Starting scan on {len(targets)} host(s)...")
    print(f"[+] Concurrency: {max_workers} threads | Timeout: {timeout}s\n")
    print(f"{'IP Address':<18} | {'Status':<10} | {'Discovery Method':<18} | {'Details'}")
    print("-" * 65)

    active_hosts = []
    inactive_hosts = []

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(probe_host, ip, timeout): ip for ip in targets}
        for future in concurrent.futures.as_completed(future_to_ip):
            try:
                res = future.result()
                if res["status"] == "Active":
                    active_hosts.append(res)
                    print(f"\033[92m{res['ip']:<18} | {res['status']:<10} | {res['method']:<18} | {res['detail']}\033[0m")
                else:
                    inactive_hosts.append(res)
            except Exception as e:
                ip = future_to_ip[future]
                print(f"[!] Error scanning {ip}: {e}", file=sys.stderr)

    elapsed = time.time() - start_time
    
    # Summary Output
    print("-" * 65)
    print(f"\n[+] Scan completed in {elapsed:.2f} seconds.")
    print(f"[+] Total Scanned: {len(targets)}")
    print(f"[+] Active Hosts : {len(active_hosts)}")
    print(f"[+] Inactive Hosts: {len(inactive_hosts)}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Network Security Discovery Scanner - Active Host Identification"
    )
    parser.add_argument(
        "range",
        help="Target IP range. Examples: 192.168.1.0/24 or 192.168.1.1-192.168.1.50"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of concurrent scan threads (default: {DEFAULT_THREADS})"
    )
    parser.add_argument(
        "-w", "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Response timeout per host in seconds (default: {DEFAULT_TIMEOUT})"
    )

    args = parser.parse_args()

    try:
        targets = parse_ip_targets(args.range)
        if not targets:
            print("[!] No valid host addresses found in provided range.")
            sys.exit(1)
        run_scanner(targets, max_workers=args.threads, timeout=args.timeout)
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        sys.exit(130)
    except ValueError as err:
        print(f"[!] Target error: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()