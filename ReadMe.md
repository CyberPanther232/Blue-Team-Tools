# Blue Team Tools - Repository for the Defenders!

![Blue Team Tools Logo](https://i.imgur.com/3j7zB3r.png)

A collection of scripts and utilities designed to assist cybersecurity professionals in defensive operations (Blue Teaming). This repository's flagship tool is the **VirusTotal IoC Scanner**.

---

## VirusTotal IoC Scanner (`vt_scanner.py`)

A powerful, multi-threaded Python script that leverages the VirusTotal API to scan Indicators of Compromise (IoCs) and report the results in a clean CSV format. This tool is designed for security analysts who need to quickly assess the reputation of IPs, domains, URLs, and file hashes.

### Features

-   **Multi-IoC Support:** Scan file hashes (MD5, SHA1, SHA256), IP addresses (IPv4 & IPv6), domains, and URLs.
-   **Automatic IoC Detection:** Use the `-m auto` mode or the `--listfile` argument to automatically determine the type of each IoC from a file.
-   **Flexible Input:** Provide IoCs as a comma-separated string (`-i`) or from a text file (`-l`).
-   **Multi-threaded:** Utilizes threading to perform scans concurrently, significantly speeding up the process for large lists.
-   **Dynamic Progress Bar:** A static progress bar keeps you informed of the scanning progress without cluttering the console.
-   **Safe Output:** All IoCs are "defanged" (e.g., `http` -> `hxxp`, `.` -> `[.]`) in the console output and final report for safe viewing.
-   **CSV Reporting:** Generates a clean, easy-to-read CSV report with the scan results, including detection stats and the last analysis date.
-   **Rate-Limit Aware:** Includes basic handling for the VirusTotal public API rate limits.

### Requirements

-   Python 3.6+
-   `requests` library

### Setup & Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/YourUsername/blue-team-tools.git
    cd blue-team-tools
    ```

2.  **Install dependencies:**
    ```bash
    pip install requests
    ```

3.  **Get your VirusTotal API Key:**
    -   You will need a free API key from VirusTotal. You can sign up on their website and find it in your profile settings.

### Usage

The script is run from the command line and accepts several arguments to customize its behavior.

**Basic Syntax:**
```bash
python3 vt_scanner.py -k <YOUR_API_KEY> [INPUT_METHOD] -o <OUTPUT_FILE.csv>
```

---

#### **Example 1: Scan a single IoC from the command line**

The script will auto-detect that this is a URL.

```bash
python3 vt_scanner.py -k YOUR_API_KEY -i "https://www.google.com" -o google_report.csv
```

---

#### **Example 2: Scan multiple comma-separated IoCs**

The script will use auto-detection for each IoC provided in the string.

```bash
python3 vt_scanner.py -k YOUR_API_KEY -i "8.8.8.8,google.com,44d88612fea8a8f36de82e1278abb02f" -o mixed_iocs.csv
```

---

#### **Example 3: Scan IoCs from a file**

Use the `--listfile` or `-l` argument to provide a file with one IoC per line. This is the recommended method for large lists. The script will auto-detect the type for each line.

**`iocs.txt`:**
```
8.8.8.8
1.1.1.1
some-malicious-domain.com
http://phishing-site.xyz/login
d41d8cd98f00b204e9800998ecf8427e
```

**Command:**
```bash
python3 vt_scanner.py -k YOUR_API_KEY -l iocs.txt -o report.csv -t 4
```
*(This example uses 4 threads for faster processing)*

---

### Example Output (`report.csv`)

The script will generate a CSV file with the following format:

| IoC                        | Malicious | Suspicious | Undetected | Harmless | Last Analysis Date  |
| -------------------------- | --------- | ---------- | ---------- | -------- | ------------------- |
| 8[.]8[.]8[.]8              | 0         | 0          | 92         | 5        | 2025-09-10 11:30:00 |
| some-malicious-domain[.]com| 15        | 2          | 75         | 0        | 2025-09-09 08:22:15 |
| hxxp[:]//phishing-site[.]xyz/login | 45 | 10 | 30 | 2 | 2025-09-10 10:05:40 |
