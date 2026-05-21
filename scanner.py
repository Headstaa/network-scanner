#!/usr/bin/env python3
import socket
import sys
import argparse
import requests
import re
from datetime import datetime

def get_arguments():
    """Handles CLI arguments professionally using argparse."""
    parser = argparse.ArgumentParser(
        description="Professional Python Vulnerability Scanner & Banner Grabber."
    )
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", dest="ports", default="1-1024", help="Port range (e.g., 22,80,443 or 1-100)")
    
    args = parser.parse_args()
    return args.target, args.ports

def parse_ports(port_arg):
    """Parses the port argument string into a list of integers."""
    if "-" in port_arg:
        start, end = map(int, port_arg.split("-"))
        return list(range(start, end + 1))
    elif "," in port_arg:
        return list(map(int, port_arg.split(",")))
    return [int(port_arg)]

def check_vulnerabilities(service_banner):
    """Queries a public API to find vulnerabilities associated with the detected banner."""
    # Extract clean software patterns (e.g., 'Apache/2.4.7' becomes 'Apache 2.4.7')
    match = re.search(r'(Apache/\d+\.\d+\.\d+|OpenSSH_\d+\.\d+)', service_banner, re.IGNORECASE)
    if not match:
        return "[-] No specific software version pattern matched for automated CVE lookup."
    
    software_query = match.group(0).replace("/", " ")
    print(f"    [i] Searching public CVE database for: {software_query}...")
    
    try:
        # Request data from public CIRCL CVE search API
        url = f"https://cve.circl.lu/api/search/{software_query.lower()}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            vulnerabilities = response.json()
            # If results are found, slice and show the top 3 items to avoid screen flooding
            if isinstance(vulnerabilities, list) and len(vulnerabilities) > 0:
                summary = f"\n    [!] WARNING: Found {len(vulnerabilities)} potential CVEs. Top vulnerabilities:\n"
                for cve in vulnerabilities[:3]:
                    summary += f"        - {cve.get('id')}: {cve.get('summary')[:90]}...\n"
                return summary
            else:
                return "    [+] No known public CVEs found for this specific version string."
        return "    [-] CVE API unavailable at the moment."
    except Exception:
        return "    [-] Could not connect to CVE Database API."
    
    try:
        # We URL-encode the space to %20 for the NIST API query
        encoded_query = software_query.replace(" ", "%20")
        url_nist = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_query}"
        
        # NIST requires a User-Agent header so it doesn't reject the script as a generic bot
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        response = requests.get(url_nist, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            # NIST v2.0 API structures vulnerabilities inside the 'vulnerabilities' key
            vulnerabilities = data.get("vulnerabilities", [])
            
            if vulnerabilities:
                summary = f"\n    [!] WARNING (Source: NIST NVD): Found {len(vulnerabilities)} potential CVEs. Top 3:\n"
                for item in vulnerabilities[:3]:
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id")
                    # Extract the English description
                    descriptions = cve_data.get("descriptions", [])
                    cve_desc = descriptions[0].get("value", "No description available.") if descriptions else ""
                    
                    summary += f"        - {cve_id}: {cve_desc[:90]}...\n"
                return summary
            else:
                return "    [+] No known public CVEs found in NIST NVD for this specific version."
                
    except Exception:
        return "    [-] Both CVE Database APIs (CIRCL & NIST) are currently unavailable."

    return "    [-] No vulnerabilities detected or APIs timed out."

def scan_port(target_ip, port):
    """Scans a specific port and attempts banner grabbing if it is open."""
    try:
        # Create TCP socket (AF_INET = IPv4, SOCK_STREAM = TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a short timeout for network efficiency
        s.settimeout(1.5)
        
        # Connect to the target on the specified port
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            try:
                # Send a basic HTTP request in case the port requires a stimulus to return a banner
                s.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            except Exception:
                banner = "No banner detected"
                
            s.close()
            return True, banner
            
        s.close()
        return False, None
    except socket.error:
        return False, None

def main():
    target, port_arg = get_arguments()
    
    # Resolve domain hostname to IP address if needed
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname '{target}'.")
        sys.exit(1)
        
    ports = parse_ports(port_arg)
    
    # Elegant initialization banner
    print("-" * 60)
    print(f" Scanning Target : {target_ip}")
    print(f" Time Started    : {str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
    print("-" * 60)
    
    try:
        for port in ports:
            is_open, banner = scan_port(target_ip, port)
            if is_open:
                print(f"[+] Port {port:5} [OPEN]")
                # Format and slice the first line of the banner cleanly
                first_line = banner.split('\n')[0] if banner else "Unknown Service"
                print(f"    Banner: {first_line[:60]}")
                
                # Execute vulnerability lookups for standard targeted services
                if "apache" in banner.lower() or "openssh" in banner.lower():
                    cve_results = check_vulnerabilities(banner)
                    print(cve_results)
                print("-" * 40)
                
    except KeyboardInterrupt:
        print("\n[-] Exiting script due to user interruption (Ctrl+C).")
        sys.exit(0)
        
    print("[+] Scan completed successfully.")

if __name__ == "__main__":
    main()