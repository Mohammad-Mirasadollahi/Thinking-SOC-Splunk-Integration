import sys
import json
import os
import gzip
import csv
import re
import requests
from datetime import datetime

# Array to cache the Splunk base path in memory
SPLUNK_BASE_PATH = []

def get_splunk_base_path():
    """
    Extracts the Splunk installation path from the /etc/init.d/splunk file
    and caches it in the SPLUNK_BASE_PATH array.
    """
    if SPLUNK_BASE_PATH:
        return SPLUNK_BASE_PATH[0]
    init_file = "/etc/init.d/splunk"
    if not os.path.exists(init_file):
        sys.stderr.write("ERROR: Splunk init file not found.\n")
        return None
    try:
        with open(init_file, "r") as file:
            for line in file:
                if "/bin/splunk" in line:
                    match = re.search(r'"([^"]+/bin/splunk)"', line)
                    if match:
                        full_path = match.group(1)
                        # Remove '/bin/splunk' to obtain the base path
                        base_path = full_path.replace("/bin/splunk", "")
                        SPLUNK_BASE_PATH.append(base_path)
                        return base_path
        sys.stderr.write("ERROR: Splunk binary path not found in init file.\n")
        return None
    except Exception as e:
        sys.stderr.write(f"ERROR reading Splunk init file: {e}\n")
        return None

# Calculate the RESULTS_DIR using the extracted base path
SPLUNK_BASE = get_splunk_base_path()
if SPLUNK_BASE is None:
    sys.stderr.write("ERROR: Cannot determine Splunk base directory.\n")
    sys.exit(4)
RESULTS_DIR = os.path.join(SPLUNK_BASE, "var", "run", "splunk", "dispatch")

PENDING_WEBHOOK_FILE = "./pending_webhooks.json"
PENDING_WEBHOOKS = []  # Global variable to hold pending webhooks

def load_pending_webhooks():
    """Load pending webhooks from a file."""
    if os.path.exists(PENDING_WEBHOOK_FILE):
        with open(PENDING_WEBHOOK_FILE, "r") as file:
            return json.load(file)
    return []

def save_pending_webhooks():
    """Save pending webhooks to a file."""
    global PENDING_WEBHOOKS
    with open(PENDING_WEBHOOK_FILE, "w") as file:
        json.dump(PENDING_WEBHOOKS, file)

def process_pending_webhooks():
    """
    Process and attempt to send any pending webhooks.
    If sending is successful, the webhook is removed from the pending list.
    """
    global PENDING_WEBHOOKS
    if not PENDING_WEBHOOKS:
        return
    remaining = []
    for pending_item in PENDING_WEBHOOKS:
        sys.stderr.write(f"INFO: Attempting to resend pending webhook for SID: {pending_item.get('sid', 'N/A')}\n")
        if not send_webhook(pending_item):
            remaining.append(pending_item)
        else:
            sys.stderr.write("INFO: Pending webhook sent successfully.\n")
    PENDING_WEBHOOKS = remaining

def extract_query_from_searchlog(sid):
    search_log_path = os.path.join(RESULTS_DIR, sid, "search.log")
    if not os.path.exists(search_log_path):
        return ""

    pattern = re.compile(
        r'INFO\s+SearchParser\s+\[.*RunDispatch\].*PARSING:\s+(search\s+.*)'
    )

    with open(search_log_path, 'r', encoding='utf-8', errors='replace') as logf:
        for line in logf:
            match = pattern.search(line)
            if match:
                return match.group(1).strip()
    return ""

def send_webhook(item):
    """
    Sends the webhook payload to the provided URL.
    Authentication is optional; if both username and password are provided,
    authentication is used. Otherwise, the webhook is sent without authentication.
    """
    webhook_url = item.get('webhook_url')
    username = item.get('username', '')
    password = item.get('password', '')

    if not webhook_url:
        sys.stderr.write("ERROR: No webhook URL provided.\n")
        return False

    payload = {
        "sid": item.get("sid", "N/A"),
        "search_name": item.get("search_name", "N/A"),
        "search_query": item.get("search_query", ""),
        "results": item.get("extracted_data", []),
        "description": item.get("description", ""),
        "severity": item.get("severity", ""),
        "kill_chain": item.get("kill_chain", ""),
        "mitre_tactics": item.get("mitre_tactics", []),
        "mitre_techniques": item.get("mitre_techniques", [])
    }

    try:
        if username and password:
            response = requests.post(
                webhook_url, json=payload,
                headers={"Content-Type": "application/json"},
                auth=(username, password)
            )
        else:
            response = requests.post(
                webhook_url, json=payload,
                headers={"Content-Type": "application/json"}
            )
        if 200 <= response.status_code < 300:
            sys.stderr.write(f"INFO: Webhook sent successfully, status: {response.status_code}\n")
            return True
        else:
            sys.stderr.write(f"ERROR: Webhook failed with status: {response.status_code}\n")
            return False
    except Exception as e:
        sys.stderr.write(f"ERROR: Failed to send webhook: {e}\n")
        return False

if __name__ == "__main__":
    PENDING_WEBHOOKS = load_pending_webhooks()
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        sys.stderr.write("FATAL: Unsupported execution mode (expected --execute flag)\n")
        sys.exit(1)

    try:
        # Process any pending webhooks before sending the current one
        process_pending_webhooks()

        settings = json.loads(sys.stdin.read())
        sid = settings.get('sid', 'N/A')
        search_name = settings.get('search_name', 'N/A')
        search_query = extract_query_from_searchlog(sid)
        
        conf = settings.get('configuration', {})
        webhook_url = conf.get('url', '')
        username = conf.get('username', '')
        password = conf.get('password', '')
        description = conf.get('description', '')
        severity = conf.get('severity', '')
        kill_chain = conf.get('kill_chain', '')
        
        # Process MITRE fields: if multiple values are entered, they should be separated by a comma.
        mitre_tactics_raw = conf.get('mitre_tactics', '')
        mitre_techniques_raw = conf.get('mitre_techniques', '')
        mitre_tactics = [x.strip() for x in mitre_tactics_raw.split(',') if x.strip()] if mitre_tactics_raw else []
        mitre_techniques = [x.strip() for x in mitre_techniques_raw.split(',') if x.strip()] if mitre_techniques_raw else []
        
        result_csv_gz = os.path.join(RESULTS_DIR, sid, "results.csv.gz")
        extracted_data = []
        if os.path.exists(result_csv_gz):
            with gzip.open(result_csv_gz, 'rt') as src:
                reader = csv.reader(src)
                for row in reader:
                    extracted_data.append(row)
            
            # Filter out columns whose header starts with "__mv_"
            if extracted_data and extracted_data[0]:
                header = extracted_data[0]
                # Determine indices of columns to keep (those that do NOT start with "__mv_")
                indices_to_keep = [i for i, field in enumerate(header) if not field.startswith("__mv_")]
                filtered_data = []
                for row in extracted_data:
                    filtered_row = [row[i] for i in indices_to_keep]
                    filtered_data.append(filtered_row)
                extracted_data = filtered_data

        else:
            sys.stderr.write(f"ERROR: No results file found for SID: {sid}\n")
            sys.exit(2)

        item = {
            "webhook_url": webhook_url,
            "username": username,
            "password": password,
            "sid": sid,
            "search_name": search_name,
            "search_query": search_query,
            "extracted_data": extracted_data,
            "description": description,
            "severity": severity,
            "kill_chain": kill_chain,
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques
        }

        if not send_webhook(item):
            PENDING_WEBHOOKS.append(item)

    except Exception as e:
        sys.stderr.write(f"ERROR: Unexpected error: {e}\n")
        sys.exit(3)
    finally:
        save_pending_webhooks()
