import os

def read_log_file(filepath):
    """
    Safely opens and reads a log file.
    Returns a list of log lines.
    """
    # Check if the file actually exists before trying to open it
    if not os.path.exists(filepath):
        print(f"Error: The file '{filepath}' was not found.")
        return []
    
    with open(filepath, 'r') as file:
        lines = file.readlines()
    
    print(f"[*] Successfully ingested {len(lines)} lines from {filepath}.")
    return lines

if __name__ == "__main__":
    # Define the target file generated on Day 2
    log_file_path = "simulated_access.log"
    
    # Execute the read function
    logs = read_log_file(log_file_path).
