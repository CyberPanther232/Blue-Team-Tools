"""
Program: vt_scanner.py
Description: A script to scan IoCs using VirusTotal API and report the results.
Author: CyberPanther232
Date: 2025-09-10

Purpose: To assist security analysts in quickly checking the status of various IoCs (IPs, domains, URLs, files) against VirusTotal's database.
"""

from threading import Thread, Lock
import requests
import json
import time
from queue import Queue
from argparse import ArgumentParser
from datetime import datetime, timezone
import hashlib # Required for URL hashing
import os # Required for file path checks
import re # Required for regex-based validation
import ipaddress # Required for robust IP address validation
import sys # Required to flush output for the progress bar

API_URL = "https://www.virustotal.com/api/v3/"

# --- Thread-safe print and progress bar ---
print_lock = Lock()
def safe_print(*args, **kwargs):
    """A thread-safe print function."""
    with print_lock:
        print(*args, **kwargs)

def print_progress_bar(completed, total, bar_length=40):
    try:
        """Prints a character-based progress bar. This will overwrite the current line."""
        percent = completed / total
        filled_length = int(bar_length * percent)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        # Use carriage return '\r' to go to the start of the line and flush to ensure it prints
        # An extra space at the end cleans up any leftover characters from previous prints
        sys.stdout.write(f'\rProgress: |{bar}| {completed}/{total} ({percent:.1%}) ')
        sys.stdout.flush()
        if completed == total:
            print() # Move to the next line after completion
    except KeyboardInterrupt:
        print("[!] Exiting program...")

# --- IoC Defanging, Validation & Determination Functions ---

def defang_ioc(ioc):
    """Replaces characters in an IoC to make it non-executable."""
    if ioc.startswith("http"):
        ioc = ioc.replace("http", "hxxp")
        ioc = ioc.replace(":", "[:]")
    
    ioc = ioc.replace(".", "[.]")
    if ioc.startswith("hxxp"):
       ioc = re.sub(r'(\w)\[\.\](\w)', r'\1.\2', ioc)

    ioc = ioc.replace("?", "[?]")
    ioc = ioc.replace("=", "[=]")
    ioc = ioc.replace("&", "[&]")
    ioc = ioc.replace("%", "[%]")
    ioc = ioc.replace("@", "[@]")
    
    return ioc

def is_valid_hash(ioc):
    """Check if the IoC is a valid MD5, SHA1, or SHA256 hash."""
    return bool(re.fullmatch(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$", ioc))

def is_valid_ip(ioc):
    """Check if the IoC is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ioc)
        return True
    except ValueError:
        return False

def is_valid_url(ioc):
    """Check if the IoC is a valid URL (simple check)."""
    return ioc.startswith("http://") or ioc.startswith("https://")

def is_valid_domain(ioc):
    """Check if the IoC is a valid domain name."""
    return bool(re.fullmatch(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", ioc))

def determine_ioc_type(ioc):
    """Determines the type of an IoC string."""
    if is_valid_hash(ioc):
        return "file"
    if is_valid_ip(ioc):
        return "ip"
    if is_valid_url(ioc):
        return "url"
    if is_valid_domain(ioc):
        return "domain"
    return None


class VTScanner:
    def __init__(self, api_key, ioc, mode):
        self.api_key = api_key
        self.ioc = ioc
        self.mode = mode
        self.endpoint = ""
        self.result = {}

    def get_report(self, log_buffer, log_lock):
        """
        Sets the correct endpoint and retrieves the report for the IoC.
        Errors and warnings are added to the log_buffer instead of printing directly.
        """
        if self.mode == "ip":
            self.endpoint = f"ip_addresses/{self.ioc}"
        elif self.mode == "domain":
            self.endpoint = f"domains/{self.ioc}"
        elif self.mode == "file":
            self.endpoint = f"files/{self.ioc}"
        elif self.mode == "url":
            url_id = hashlib.sha256(self.ioc.encode()).hexdigest()
            self.endpoint = f"urls/{url_id}"
        else:
            with log_lock:
                log_buffer.append(f"Error: Invalid mode '{self.mode}' for ioc '{self.ioc}'")
            return False

        headers = {"x-apikey": self.api_key}
        
        try:
            # Add a small delay to respect public API rate limits (4 requests/minute)
            time.sleep(1) 
            response = requests.get(API_URL + self.endpoint, headers=headers)

            if response.status_code == 200:
                report = response.json()
                attributes = report.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                last_analysis_date = attributes.get("last_analysis_date", 0)

                self.result = {
                    "ioc": self.ioc,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "date": datetime.fromtimestamp(last_analysis_date, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if last_analysis_date else "N/A"
                }
                return True
            elif response.status_code == 404:
                return False # Not found is not an error, just no result
            elif response.status_code == 429:
                with log_lock:
                    log_buffer.append(f"[!] Rate limit exceeded for {defang_ioc(self.ioc)}. Waiting...")
                time.sleep(60) # Wait for 60 seconds if rate limited
                return self.get_report(log_buffer, log_lock) # Retry the request
            else:
                with log_lock:
                    log_buffer.append(f"[!] API Error for {defang_ioc(self.ioc)}: {response.status_code} - {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            with log_lock:
                log_buffer.append(f"[!] Network error for {defang_ioc(self.ioc)}: {e}")
            return False

def generate_report(output_file, results):
    """Generates a CSV report from the collected results."""
    safe_print(f"\n[*] Generating report at: {output_file}")
    with open(output_file, 'w') as f:
        f.write("IoC,Malicious,Suspicious,Undetected,Harmless,Last Analysis Date\n")
        for result in results:
            res_data = result['result']
            defanged_ioc = defang_ioc(res_data['ioc'])
            f.write(f"{defanged_ioc},{res_data['malicious']},{res_data['suspicious']},{res_data['undetected']},{res_data['harmless']},{res_data['date']}\n")
    safe_print("[+] Report generation complete.")

def worker(queue, results, total_iocs, completed_count, progress_lock, log_buffer, log_lock):
    """Worker thread function to process IoCs from the queue."""
    while not queue.empty():
        scanner = queue.get()
        
        if scanner.get_report(log_buffer, log_lock):
            results.append({'ioc': scanner.ioc, 'result': scanner.result})
        
        with progress_lock:
            completed_count[0] += 1
            # Now, handle printing logs and the progress bar together
            with print_lock:
                # Check for and print any new log messages
                with log_lock:
                    if log_buffer:
                        # Clear the current progress bar line before printing logs
                        sys.stdout.write('\r' + ' ' * 80 + '\r')
                        for msg in log_buffer:
                            print(msg)
                        log_buffer.clear()
                
                # Redraw the progress bar on the last line
                print_progress_bar(completed_count[0], total_iocs)

        queue.task_done()

def main():
    parser = ArgumentParser(description="Scan IoCs using VirusTotal API. Use -l for a file of IoCs or -i for a single/comma-separated string.")
    parser.add_argument("-k", "--apikey", required=True, help="VirusTotal API Key")
    parser.add_argument("-i", "--input", help="Input a single IoC or a comma-separated string of IoCs.")
    parser.add_argument("-l", "--listfile", help="Input file with one IoC per line. Auto-detection is used for each IoC.")
    parser.add_argument("-m", "--mode", choices=["ip", "domain", "url", "file", "auto"], default="auto", help="Type of IoC to scan for --input argument. Defaults to 'auto'.")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file for results")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads to use (1-4 recommended for public API)")
    args = parser.parse_args()

    # --- Input Validation ---
    if not args.input and not args.listfile:
        parser.error("No input provided. Please use --input or --listfile.")
    if args.input and args.listfile:
        parser.error("Please provide either --input or --listfile, not both.")
    if args.apikey == "YOUR_API_KEY" or len(args.apikey) < 64:
        safe_print("Error: Please provide a valid VirusTotal API key.")
        return
    if not (1 <= args.threads <= 10):
        safe_print("Error: Number of threads must be between 1 and 10.")
        return
    
    # --- Read IoCs ---
    iocs_to_scan = []
    if args.listfile:
        if not os.path.exists(args.listfile):
            safe_print(f"Error: Input file not found at '{args.listfile}'")
            return
        safe_print(f"[*] Reading IoCs from file for auto-detection: {args.listfile}")
        with open(args.listfile, 'r') as f:
            iocs_to_scan = [line.strip() for line in f if line.strip()]
    elif args.input:
        safe_print(f"[*] Treating input as a comma-separated string.")
        iocs_to_scan = [ioc.strip() for ioc in args.input.split(',') if ioc.strip()]

    # --- Setup IoC Queue ---
    try:
        queue = Queue()
        
        for ioc in iocs_to_scan:
            current_mode = args.mode
            if args.listfile or args.mode == 'auto':
                current_mode = determine_ioc_type(ioc)
            
            if current_mode:
                if args.mode == 'auto' or args.listfile:
                    safe_print(f"[*] Detected '{defang_ioc(ioc)}' as type: {current_mode}")
                scanner = VTScanner(api_key=args.apikey, ioc=ioc, mode=current_mode)
                queue.put(scanner)
            else:
                safe_print(f"[!] Warning: Could not determine type for '{defang_ioc(ioc)}'. Skipping.")

        if queue.empty():
            safe_print("[!] No valid IoCs were found to scan.")
            return

        results = []
        threads = []
        total_items = queue.qsize()
        completed_count = [0] # Use a list for mutability across threads
        progress_lock = Lock()
        log_buffer = []
        log_lock = Lock()
        
        safe_print(f"\n[*] Starting scan for {total_items} IoCs with {args.threads} threads...")
        print_progress_bar(0, total_items) # Print initial empty bar

        for _ in range(args.threads):
            thread = Thread(target=worker, args=(queue, results, total_items, completed_count, progress_lock, log_buffer, log_lock))
            thread.start()
            threads.append(thread)

        queue.join()
        for thread in threads:
            thread.join()

        # Final check for any remaining log messages
        if log_buffer:
            sys.stdout.write('\r' + ' ' * 80 + '\r')
            for msg in log_buffer:
                print(msg)

        if results:
            generate_report(args.output, results)
        else:
            safe_print("[!] No results were successfully retrieved.")
    except KeyboardInterrupt:
        print("[!] Keyboard interruption detected! Shutting down!")
        exit(0)

if __name__ == "__main__":
    main()

