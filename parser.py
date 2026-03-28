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

def extract_unique_ips(log_lines):
    """
    Parses raw log lines to extract unique IPv4 addresses.
    Utilizes a Python 'set' to automatically drop duplicate IPs.
    """
    # Standard Regex pattern for matching an IPv4 address
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    unique_ips = set()
    
    for line in log_lines:
        match = re.search(ip_pattern, line)
        if match:
            # If an IP is found, add it to the set
            unique_ips.add(match.group())
            
    print(f"[*] Extraction complete: Found {len(unique_ips)} unique IPs to investigate.")
    
    # Convert the set back to a list so it can be iterated over later
    return list(unique_ips)

if __name__ == "__main__":
    log_file_path = "simulated_access.log"
    
    # 1. Ingest the logs
    logs = read_log_file(log_file_path)
    
    # 2. Extract the IPs
    if logs:
        target_ips = extract_unique_ips(logs)
        
        # Print a sample of 5 IPs to verify the logic works
        print(f"[*] Sample of IPs extracted: {target_ips[:5]}")
