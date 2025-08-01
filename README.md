# Network Scanner & Vulnerability Identifier

## Project Description
This is a Python-based command-line tool designed for network reconnaissance and basic security assessment. It can discover active hosts on a given network range, scan for open ports using various techniques, identify services running on those ports through banner grabbing, and perform a preliminary vulnerability assessment based on known service versions. The tool provides clear console output and can generate reports in text and CSV formats.

## Features
- **Host Discovery:**
    - Active host detection using ARP scanning for local networks.
    - ICMP (ping) scanning for general host reachability.
- **Port Scanning:**
    - **TCP Connect Scan (`-sT`):** Performs a full TCP handshake to identify open ports.
    - **TCP SYN Scan (`-sS`):** Implements a "half-open" scan, often considered stealthier.
    - **UDP Scan (`-sU`):** Basic detection of open/filtered UDP ports.
    - Utilizes multi-threading for efficient and faster scanning.
- **Service Enumeration & Banner Grabbing:**
    - Attempts to identify the service and version running on open TCP/UDP ports.
    - Parses common service banners (e.g., HTTP, SSH, FTP).
- **Basic Vulnerability Identification:**
    - Checks identified service versions against a local, static `vulnerabilities.json` database for known CVEs.
- **Reporting:**
    - Structured and visually appealing console output using the `rich` library.
    - Ability to save scan results to a text file (`.txt`).
    - Ability to save structured scan results to a Comma Separated Values (CSV) file (`.csv`).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Aftab4732/network-scanner.git](https://github.com/Aftab4732/network-scanner.git)
    cd network-scanner
    ```
    (Replace `YourGitHubUsername` and `network-scanner.git` with your actual GitHub repository URL.)

2.  **Create and activate a Python virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    (This will install `scapy`, `python-nmap`, `rich`, etc.)

4.  **Prepare the Vulnerability Database:**
    Ensure the `vulnerabilities.json` file is present in the root directory of the project. This file serves as the local vulnerability lookup database.

## Usage

This tool requires **root privileges (`sudo`)** for raw socket operations (ARP, ICMP, SYN, UDP scans). It's recommended to use the full path to your virtual environment's Python interpreter when running with `sudo`.

**General Syntax:**
```bash
sudo /path/to/your/venv/bin/python3 src/main.py <TARGET_IP_RANGE> [OPTIONS]
```

**Examples:**

1. **Default TCP Connect Scan (verbose output):**
```bash
> sudo /path/to/your/venv/bin/python3 src/main.py 192.168.1.0/24 -v 
```
2. **TCP SYN Scan (stealthy, verbose output):**
```bash
sudo /path/to/your/venv/bin/python3 src/main.py 192.168.1.0/24 -sS -v
```
3. **UDP Scan (verbose output):**
```bash
sudo /path/to/your/venv/bin/python3 src/main.py 192.168.1.0/24 -sU -v
```
4. **Save results to a text file:**
```bash
sudo /path/to/your/venv/bin/python3 src/main.py 192.168.1.0/24 -sT -o scan_report.txt -f txt
```
5. **Save results to a CSV file (verbose):**
```bash
sudo /path/to/your/venv/bin/python3 src/main.py 192.168.1.0/24 -sS -v -o scan_results.csv -f csv
```

## Vulnerability Database (vulnerabilities.json)

This tool uses a simplified, local JSON file (vulnerabilities.json) to store a mapping of known service versions to associated CVE IDs and descriptions. This database needs to be manually maintained. For a production-grade scanner, integration with live, comprehensive vulnerability databases (like NVD) would be required.

## Learning Outcomes

- During the development of this project, I gained practical experience in:

- **Network basics:** IP addressing, subnets, ARP, ICMP.

- Network reconnaissance techniques: Host discovery, port scanning, banner grabbing.

- **Python programming:**
    - argparse for robust command-line interfaces.
    - scapy for low-level packet crafting and sniffing (ARP, ICMP, SYN/UDP scans).
    - socket for raw TCP connections and banner grabbing.
    - threading and queue for implementing multi-threaded, concurrent operations.
    - File I/O for report generation (.txt, .csv).
    - json for data management.
    - rich for enhancing command-line interface aesthetics.
    - Basic vulnerability identification concepts and their reliance on version information.

## Future Enhancements (Ideas for continued development)

- Integrate with official vulnerability databases (e.g., NVD API) for real-time, comprehensive vulnerability data.

- Implement more advanced port scanning techniques (e.g., Xmas, Null, FIN scans).

- Add specific protocol-aware probes for better UDP and complex TCP service enumeration.

- Develop a basic web-based GUI for easier interaction.

- Incorporate python-nmap for leveraging Nmap's powerful scanning engine.

- Implement OS detection (e.g., via Nmap or scapy fingerprinting).

- Add support for different IP range formats (e.g., comma-separated IPs).

## Acknowledgments

- **Scapy:** Powerful packet manipulation program.

- **Rich:** A Python library for rich text and beautiful formatting in the terminal.

- **Python standard library:** For modules like argparse, socket, threading, queue, json, csv, re.
