import os
import re
import time
import logging
import requests
from dotenv import load_dotenv
from typing import List, Dict
from tqdm import tqdm

# Configure logging (Saving to a file and printing to console)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("parser_execution.log"),
        logging.StreamHandler()
    ]
)

load_dotenv()
API_KEY = os.getenv('ABUSEIPDB_API_KEY')

def read_log_file(filepath: str) -> List[str]:
    if not os.path.exists(filepath):
        logging.error(f"The file '{filepath}' was not found.")
        return []
    with open(filepath, 'r') as file:
        lines = file.readlines()
    logging.info(f"Successfully ingested {len(lines)} lines from {filepath}.")
    return lines

def parse_log_behaviors(log_lines: List[str]) -> Dict[str, Dict[str, int]]:
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

def check_ip_reputation(ip: str) -> int:
    """Queries AbuseIPDB and returns the threat score."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': API_KEY}
    
    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring, timeout=10)
        if response.status_code == 200:
            return response.json()['data']['abuseConfidenceScore']
        elif response.status_code == 429:
            logging.warning("Rate limit hit! Halting API requests.")
            return -1 # Custom code to indicate rate limit
        else:
            logging.error(f"API Error for IP {ip}: Status {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Connection Error: {e}")
        return None

if __name__ == "__main__":
    if not API_KEY:
        logging.error("ABUSEIPDB_API_KEY not found in .env file.")
        exit()

    log_file_path = "simulated_access.log"
    logs = read_log_file(log_file_path)
    
    if logs:
        threat_data = parse_log_behaviors(logs)
        unique_ips = list(threat_data.keys())
        
        logging.info("Commencing Threat Intelligence Enrichment...")
        
        # We cap at 100 to protect your free API tier limits. 
        target_ips = unique_ips[:100]
        enriched_data = {}

        # Wrap the loop in tqdm for a progress bar
        for ip in tqdm(target_ips, desc="Querying AbuseIPDB", unit="ip"):
            score = check_ip_reputation(ip)
            
            if score == -1:
                break # Stop the loop entirely if rate limit is hit
                
            if score is not None:
                enriched_data[ip] = {
                    'behavior': threat_data[ip],
                    'abuse_score': score
                }
            
            # STRICT RATE LIMITING: Pause for 1 second between requests
            time.sleep(1) 
            
        logging.info(f"Enrichment complete. Successfully scored {len(enriched_data)} IPs.")