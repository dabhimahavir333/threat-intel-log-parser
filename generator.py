import random
import time
from datetime import datetime, timedelta

# List of simulated "malicious" IPs we want our parser to flag later
MALICIOUS_IPS = [
    "185.153.196.22", 
    "45.134.144.112", 
    "193.169.255.78", 
    "89.248.165.13"
]

def generate_random_ip():
    """Generates a random IPv4 address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_log_entry(timestamp):
    """Generates a single Apache combined log format entry."""
    # 5% chance to inject a known malicious IP, 95% chance for a random IP
    if random.random() < 0.05:
        ip = random.choice(MALICIOUS_IPS)
    else:
        ip = generate_random_ip()

    methods = ["GET", "POST", "PUT", "HEAD"]
    resources = ["/index.html", "/login.php", "/api/v1/data", "/wp-admin", "/images/logo.png"]
    statuses = [200, 301, 401, 403, 404, 500]
    
    method = random.choice(methods)
    resource = random.choice(resources)
    status = random.choice(statuses)
    
    # Apache log time format: [19/Mar/2026:11:05:32 +0530]
    time_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0530")
    
    # Standard Apache Combined Log format
    log_line = f'{ip} - - [{time_str}] "{method} {resource} HTTP/1.1" {status} {random.randint(100, 5000)} "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n'
    return log_line

def main():
    print("Generating simulated Apache access logs...")
    log_file = "simulated_access.log"
    num_lines = 5000
    
    # Start time is 7 days ago from today
    current_time = datetime.now() - timedelta(days=7)
    
    with open(log_file, "w") as f:
        for _ in range(num_lines):
            f.write(generate_log_entry(current_time))
            # Advance time by a few random seconds per log entry
            current_time += timedelta(seconds=random.randint(1, 15))
            
    print(f"Successfully generated {num_lines} log entries in {log_file}")

if __name__ == "__main__":
    main().
