import os
import re
import logging
from typing import List, Dict

# Configure enterprise-grade logging output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def read_log_file(filepath: str) -> List[str]:
    """Safely opens and reads a log file, returning a list of strings."""
    if not os.path.exists(filepath):
        logging.error(f"The file '{filepath}' was not found.")
        return []
    
    with open(filepath, 'r') as file:
        lines = file.readlines()
    
    logging.info(f"Successfully ingested {len(lines)} lines from {filepath}.")
    return lines

def parse_log_behaviors(log_lines: List[str]) -> Dict[str, Dict[str, int]]:
    """
    Extracts the IP, HTTP Method, URI, and Status Code.
    Maps each unique IP to its request behavior.
    """
    log_pattern = re.compile(
        r'(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)'   
        r'.*?"(?P<method>[A-Z]+)'                      
        r'\s+(?P<uri>[^\s]+)'                          
        r'.*?"\s+(?P<status>\d{3})'                    
    )
    
    ip_behaviors = {}
    
    for line in log_lines:
        match = log_pattern.search(line)
        if match:
            ip = match.group('ip')
            status = match.group('status')
            
            if ip not in ip_behaviors:
                ip_behaviors[ip] = {'total_requests': 0, 'failed_attempts': 0, 'successful_attempts': 0}
                
            ip_behaviors[ip]['total_requests'] += 1
            
            if status.startswith('4') or status.startswith('5'):
                ip_behaviors[ip]['failed_attempts'] += 1
            elif status.startswith('2'):
                ip_behaviors[ip]['successful_attempts'] += 1
                
    logging.info(f"Behavioral parsing complete. Analyzed {len(ip_behaviors)} unique IPs.")
    return ip_behaviors

if __name__ == "__main__":
    log_file_path = "simulated_access.log"
    
    logging.info("Initializing Threat Intelligence Log Parser...")
    logs = read_log_file(log_file_path)
    
    if logs:
        threat_data = parse_log_behaviors(logs)
        
        # Log the data for the first 3 IPs to verify it works
        sample_ips = list(threat_data.keys())[:3]
        for ip in sample_ips:
            logging.info(f"IP: {ip} | Data: {threat_data[ip]}")