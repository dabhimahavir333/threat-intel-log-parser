import os
import re

def read_log_file(filepath):
    """Safely opens and reads a log file."""
    if not os.path.exists(filepath):
        print(f"Error: The file '{filepath}' was not found.")
        return []
    
    with open(filepath, 'r') as file:
        lines = file.readlines()
    
    print(f"[*] Successfully ingested {len(lines)} lines from {filepath}.")
    return lines

def parse_log_behaviors(log_lines):
    """
    Extracts the IP, HTTP Method, URI, and Status Code.
    Maps each unique IP to its request behavior (successes vs. failures).
    """
    # Advanced Regex utilizing Named Capture Groups (?P<name>pattern)
    log_pattern = re.compile(
        r'(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)'   # Captures IP Address
        r'.*?"(?P<method>[A-Z]+)'                      # Captures HTTP Method (GET, POST)
        r'\s+(?P<uri>[^\s]+)'                          # Captures the URI requested
        r'.*?"\s+(?P<status>\d{3})'                    # Captures the 3-digit Status Code
    )
    
    ip_behaviors = {}
    
    for line in log_lines:
        match = log_pattern.search(line)
        if match:
            ip = match.group('ip')
            status = match.group('status')
            
            # Initialize the IP in our dictionary if it is the first time we see it
            if ip not in ip_behaviors:
                ip_behaviors[ip] = {'total_requests': 0, 'failed_attempts': 0, 'successful_attempts': 0}
                
            ip_behaviors[ip]['total_requests'] += 1
            
            # 4xx (Client Error) and 5xx (Server Error) often indicate scanning or brute-forcing
            if status.startswith('4') or status.startswith('5'):
                ip_behaviors[ip]['failed_attempts'] += 1
            elif status.startswith('2'):
                ip_behaviors[ip]['successful_attempts'] += 1
                
    print(f"[*] Behavioral parsing complete. Analyzed {len(ip_behaviors)} unique IPs.")
    return ip_behaviors

if __name__ == "__main__":
    log_file_path = "simulated_access.log"
    
    logs = read_log_file(log_file_path)
    
    if logs:
        # Extract the behavioral data
        threat_data = parse_log_behaviors(logs)
        
        # Print the data for the first 3 IPs to verify it works
        sample_ips = list(threat_data.keys())[:3]
        for ip in sample_ips:
            print(f"IP: {ip} | Data: {threat_data[ip]}")