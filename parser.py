import os
import re
import requests
from dotenv import load_dotenv

# Securely load API Key from the hidden .env file
load_dotenv()
API_KEY = os.getenv('ABUSEIPDB_API_KEY')

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
    """Extracts the IP and maps request behavior."""
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
    print(f"[*] Behavioral parsing complete. Analyzed {len(ip_behaviors)} unique IPs.")
    return ip_behaviors

def check_ip_reputation(ip):
    """
    Queries the AbuseIPDB API for a specific IP address.
    Returns the abuse confidence score (0 to 100).
    """
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    
    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        if response.status_code == 200:
            data = response.json()
            return data['data']['abuseConfidenceScore']
        else:
            print(f"[-] API Error for IP {ip}: Status {response.status_code}")
            return None
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return None

if __name__ == "__main__":
    # Halt execution if the API key is missing
    if not API_KEY:
        print("Error: ABUSEIPDB_API_KEY not found in .env file.")
        exit()

    log_file_path = "simulated_access.log"
    logs = read_log_file(log_file_path)
    
    if logs:
        threat_data = parse_log_behaviors(logs)
        
        print("\n[*] Commencing Threat Intelligence Enrichment (Testing first 5 IPs)...")
        unique_ips = list(threat_data.keys())
        
        # Test only the first 5 to preserve your free tier API limits
        for ip in unique_ips[:5]:
            score = check_ip_reputation(ip)
            if score is not None:
                print(f"IP: {ip} | Total Requests: {threat_data[ip]['total_requests']} | Abuse Score: {score}%")