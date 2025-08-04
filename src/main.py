import argparse
import sys
import os
import threading
import queue
import socket
import json
import re
import csv
from scapy.all import Ether, ARP, srp, conf, IP, ICMP, sr, TCP, sr1, send, UDP 
from ipaddress import ip_network, ip_address
from rich.console import Console 
from rich.table import Table     
from rich.padding import Padding 
from rich.panel import Panel  
from rich import print as rprint 
# ... (all imports) ...

console = Console() # Initialize Rich Console for styled output
# Common ports to scan
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080, 8443
]
# Common UDP ports to scan
COMMON_UDP_PORTS = [
    53,   # DNS
    67,   # DHCP (server)
    68,   # DHCP (client)
    69,   # TFTP
    123,  # NTP
    161,  # SNMP
    162,  # SNMP traps
    500,  # ISAKMP (IPsec VPN)
    514,  # Syslog
]
# Number of threads for concurrent scanning
THREADS = 50 # A good starting point, adjust based on network stability and system resources
def parse_arguments():
    """
    Parses command-line arguments for the network scanner.
    """
    parser = argparse.ArgumentParser(
        description="A simple network scanner to discover active hosts and open ports."
    )

    # Required argument for target IP range
    parser.add_argument(
        "target",
        metavar="TARGET_IP_RANGE",
        help="The target IP range to scan (e.g., 192.168.1.0/24 or 192.168.1.1-192.168.1.255)"
    )

    # argument for verbose output
    parser.add_argument(
        "-v", "--verbose",
        action="store_true", # Stores True if the flag is present, False otherwise
        help="Enable verbose output for detailed information"
    )
    # argument for scan type
    parser.add_argument(
        "-sT", "--tcp-connect",
        action="store_true",
        help="Perform a TCP Connect scan (default if no scan type specified)"
    )
    parser.add_argument(
        "-sS", "--tcp-syn",
        action="store_true",
        help="Perform a TCP SYN (Stealth) scan (requires root)"
    )
    parser.add_argument(
        "-sU", "--udp-scan",
        action="store_true",
        help="Perform a UDP scan (requires root)"
    )
        # ---arguments for reporting ---
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save scan results to an output file"
    )
    parser.add_argument(
        "-f", "--format",
        choices=['txt', 'csv'], # Restrict format choices
        default='txt', # Default to text format if not specified
        help="Output format for the report (txt or csv)"
    )
    # ---arguments for reporting ---

    args = parser.parse_args()
    
    # --- Logic for default scan type if none specified ---
    if not args.tcp_connect and not args.tcp_syn and not args.udp_scan: # Corrected this line
        args.tcp_connect = True # Default to TCP Connect

    # Basic validation: ensure only one scan type is chosen (optional but good)
    selected_scan_types = sum([args.tcp_connect, args.tcp_syn, args.udp_scan])
    if selected_scan_types > 1:
        parser.error("Please choose only one scan type (-sT, -sS, or -sU).")
    return args

# Suppress Scapy warnings

def get_ip_range_ips(target_range):
    """
    Parses the target IP range (CIDR or hyphenated) and returns a list of IP addresses.
    """
    ips = []
    try:
        # Try parsing as CIDR (e.g., 192.168.1.0/24)
        network = ip_network(target_range, strict=False)
        ips = [str(ip) for ip in network.hosts()] # .hosts() excludes network/broadcast addresses
        # For small subnets like /30, /31, /32, .hosts() might be empty, so include the network address itself
        if not ips and network.num_addresses > 0:
            ips = [str(ip) for ip in network] # include network/broadcast if hosts is empty

    except ValueError:
        # Try parsing as hyphenated range (e.g., 192.168.1.1-192.168.1.255)
        if '-' in target_range:
            parts = target_range.split('-')
            if len(parts) == 2:
                start_ip_str = parts[0]
                end_ip_str = parts[1]

                # Basic validation 
                start_ip_octets = list(map(int, start_ip_str.split('.')))
                end_ip_octets = list(map(int, end_ip_str.split('.')))

                if len(start_ip_octets) == 4 and len(end_ip_octets) == 4:
                    # Iterate through the last octet for simplicity (assumes /24-like range)
                    # This is a simplification; a full IP range iterator is more complex
                    if start_ip_octets[0:3] == end_ip_octets[0:3]: # Check if first 3 octets match
                        for i in range(start_ip_octets[3], end_ip_octets[3] + 1):
                            ips.append(f"{start_ip_octets[0]}.{start_ip_octets[1]}.{start_ip_octets[2]}.{i}")
                    else:
                        print(f"[!] Warning: Hyphenated range '{target_range}' is not in a simple X.X.X.Y-Z format. Scanning only the first IP.")
                        ips.append(start_ip_str) # Fallback to just scanning the first IP
                else:
                    print(f"[!] Warning: Invalid hyphenated IP format '{target_range}'. Scanning only the first IP.")
                    ips.append(start_ip_str) # Fallback to just scanning the first IP
            else:
                print(f"[!] Warning: Invalid hyphenated IP range format '{target_range}'. Scanning only the first IP.")
                ips.append(target_range.split('-')[0]) # Fallback to just scanning the first IP
        else:
            # Assume single IP if neither CIDR nor hyphenated
            ips.append(target_range)

    if not ips:
        print(f"[!] Could not parse target IP range: {target_range}. No IPs to scan.")
        sys.exit(1)
    return ips


def arp_scan(target_ips, verbose=False):
    """
    Performs an ARP scan on the given list of IP addresses.
    Returns a list of active IP addresses.
    """
    active_hosts = []

    if verbose:
        print(f"[*] Initiating ARP scan for {len(target_ips)} IPs...")

    # Craft the ARP request packet
    # Ether(): This is the Ethernet layer. We set the destination MAC to broadcast (ff:ff:ff:ff:ff:ff)
    #          so all devices on the local network receive it.
    # ARP(pdst=ip): This is the ARP layer. 'pdst' is the target IP address.
    #                'hwsrc' (source MAC) and 'psrc' (source IP) are usually auto-filled by Scapy
    #                based on your interface.
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ips) # Scapy allows passing a list to pdst!

    # Send the packet and wait for responses
    # timeout: How long to wait for responses.
    # verbose=False: Suppresses Scapy's internal output for cleaner script output.
    # filter="arp and host {our_ip}": This is a BPF filter to only capture ARP replies destined for our IP.
    #                                  (While srp usually handles this, it's good practice for sniffer functions)
    # Note: Scapy's srp can be tricky with specific interface selection in all cases.
    #       It usually picks the correct one based on routing. If issues arise, we can
    #       add 'iface="your_interface_name"' to srp.
    try:
        # srp returns two lists: answered and unanswered packets
        answered, unanswered = srp(arp_request, timeout=2, verbose=False, iface="wlan0") # <--- ADD THIS# Increased timeout slightly
    except Exception as e:
        print(f"[!] An error occurred during ARP scan: {e}")
        print("[!] This might be due to insufficient permissions or network issues.")
        return [] # Return empty list on error

    # Process answered packets
    for sent, received in answered:
        # The 'received' packet is an ARP reply from an active host
        # received.psrc contains the IP address of the responding host
        # received.hwsrc contains the MAC address of the responding host
        active_ip = received.psrc
        active_mac = received.hwsrc
        active_hosts.append(active_ip)
        if verbose:
            print(f"    [+] Host active: {active_ip} ({active_mac})")

    if verbose and not active_hosts:
        print("    [-] No active hosts found via ARP scan in the specified range.")
    elif verbose and active_hosts:
        print(f"[*] ARP scan completed. Found {len(active_hosts)} active hosts.")

    return active_hosts

# ... (existing functions like get_ip_range_ips, arp_scan) ...

def icmp_ping_scan(target_ips, verbose=False):
    """
    Performs an ICMP ping scan on the given list of IP addresses.
    Returns a list of active IP addresses.
    """
    active_hosts = []

    if verbose:
        print(f"[*] Initiating ICMP ping scan for {len(target_ips)} IPs...")

    # Craft the ICMP Echo Request packet
    # IP(dst=ip): This is the IP layer. 'dst' is the target IP address.
    # ICMP(): This is the ICMP layer, default is Echo Request.
    # We'll use sr (Send and Receive Layer 3 packets) instead of srp (Layer 2)
    # srp is for raw ethernet frames, sr is for IP packets.
    # Scapy can handle a list of destinations for IP packets.

    # Create a list of ICMP ping packets for each target IP
    icmp_packets = [IP(dst=ip)/ICMP() for ip in target_ips]

    try:
        # Send the packets and wait for responses
        # timeout: How long to wait for responses for each packet.
        # retry: Number of times to retry sending unanswered packets.
        # verbose=False: Suppresses Scapy's internal output.
        answered, unanswered = sr(icmp_packets, timeout=1, verbose=False, retry=0) # Shorter timeout, no retries for speed
    except Exception as e:
        print(f"[!] An error occurred during ICMP ping scan: {e}")
        print("[!] This might be due to insufficient permissions, firewall, or network issues.")
        return [] # Return empty list on error

    # Process answered packets
    for sent_packet, received_packet in answered:
        # The 'received_packet' is an ICMP Echo Reply from an active host
        active_ip = received_packet.src # Source IP of the reply is the active host
        active_hosts.append(active_ip)
        if verbose:
            print(f"    [+] Host active (ICMP): {active_ip}")

    if verbose and not active_hosts:
        print("    [-] No active hosts found via ICMP ping scan in the specified range.")
    elif verbose and active_hosts:
        print(f"[*] ICMP ping scan completed. Found {len(active_hosts)} active hosts.")

    return active_hosts

# ... (existing imports, ensure you have 'IP' and 'ICMP' in the scapy.all import) ...
# from scapy.all import Ether, ARP, srp, conf, IP, ICMP # This line should be at the top

# ... (all your existing functions: parse_arguments, get_ip_range_ips, arp_scan, icmp_ping_scan) ...
# ... (existing functions like icmp_ping_scan) ...


def check_port(target_ip, port, timeout, open_ports_queue, verbose):
    """
    Attempts to establish a TCP connection to a single port.
    Puts the port into open_ports_queue if successful.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target_ip, port))

        if result == 0:
            open_ports_queue.put(port) # Put the open port into the queue
            if verbose:
                print(f"    [+] Port {port} on {target_ip} is OPEN")
        # else: (optional: print closed/filtered)
        #     if verbose and result != 111:
        #         print(f"    [-] Port {port} on {target_ip} is {socket.error(result).strerror}")

    except socket.timeout:
        if verbose:
            print(f"    [-] Port {port} on {target_ip} timed out (filtered/slow)")
    except socket.error as e:
        if verbose:
            print(f"    [-] Port {port} on {target_ip} error: {e}")
    finally:
        sock.close()

def tcp_connect_scan_threaded(target_ip, ports, timeout=0.5, verbose=False):
    """
    Performs a TCP Connect scan on a single target IP for the given ports using multi-threading.
    Returns a list of open ports.
    """
    if verbose:
        print(f"[*] Starting TCP Connect scan for {target_ip} on {len(ports)} ports using {THREADS} threads...")

    ports_to_scan_queue = queue.Queue() # Queue to hold ports that need scanning
    open_ports_queue = queue.Queue()    # Queue to hold discovered open ports

    # Populate the ports_to_scan_queue
    for port in ports:
        ports_to_scan_queue.put(port)

    threads = []
    # Create and start worker threads
    for _ in range(THREADS):
        thread = threading.Thread(
            target=worker_scan_port, # This will be our worker function
            args=(target_ip, ports_to_scan_queue, open_ports_queue, timeout, verbose)
        )
        thread.daemon = True # Allows the main program to exit even if threads are still running
        thread.start()
        threads.append(thread)

    # Wait for all ports to be processed in the input queue
    ports_to_scan_queue.join()

    # Collect results from the open_ports_queue
        # Give threads a moment to fully finish and clean up
        # This loop waits for all threads to truly complete, not just for the queue to empty
    for thread in threads:
            if thread.is_alive():
                thread.join(timeout=0.1) # Wait for a short duration
        
        # Collect results from the open_ports_queue
    discovered_open_ports = []
        # Use a try-except to safely get from queue after join() to prevent potential blocking
    while not open_ports_queue.empty():
            try:
                discovered_open_ports.append(open_ports_queue.get_nowait())
            except queue.Empty:
                break #

    if verbose:
        print(f"[*] TCP Connect scan for {target_ip} completed. Found {len(discovered_open_ports)} open ports.")

    return discovered_open_ports


def worker_scan_port(target_ip, ports_to_scan_queue, open_ports_queue, timeout, verbose):
    """
    Worker function for threads: picks a port from the queue, scans it, and puts result.
    """
    while True:
        try:
            port = ports_to_scan_queue.get(timeout=1) # Get a port from the queue
            check_port(target_ip, port, timeout, open_ports_queue, verbose)
            ports_to_scan_queue.task_done() # <--- Move task_done() here
        except queue.Empty:
            break # No more ports to scan
        except Exception as e:
            # Handle unexpected errors in scan logic without crashing the worker
            if verbose:
                print(f"    [!] Error in TCP worker for {target_ip}: {e}")
            ports_to_scan_queue.task_done() # Still mark task done even on error, to avoid hanging join()# Mark the task as done


def check_syn_port(target_ip, port, timeout, open_ports_queue, verbose):
    """
    Performs a SYN scan on a single port using Scapy.
    Puts the port into open_ports_queue if successful.
    """
    # Craft the SYN packet: IP layer (destination) / TCP layer (destination port, SYN flag)
    # flags="S" sets the SYN flag. dport is the destination port.
    syn_packet = IP(dst=target_ip)/TCP(dport=port, flags="S")

    try:
        # Send the SYN packet and wait for a single response (SYN-ACK or RST)
        # timeout: how long to wait for a response
        # verbose=False: suppress Scapy's internal output
        # retry=0: don't retry sending if no response
        resp = sr1(syn_packet, timeout=timeout, verbose=False, retry=0)

        if resp and resp.haslayer(TCP):
            # Check for SYN-ACK (0x12 or S.A) indicates port is open
            if resp.getlayer(TCP).flags == 0x12: # SYN-ACK
                # If SYN-ACK received, send RST to close half-open connection
                # We send a RST (flags="R") with the same sequence and acknowledgement numbers
                # to gracefully tear down the half-open connection.
                rst_packet = IP(dst=target_ip)/TCP(dport=port, flags="R", seq=resp.ack, ack=resp.seq + 1)
                send(rst_packet, verbose=False) # send() is for sending packets without expecting response
                open_ports_queue.put(port)
                if verbose:
                    print(f"    [+] Port {port} on {target_ip} is OPEN (SYN)")
            # Check for RST (0x04 or R) indicates port is closed
            elif resp.getlayer(TCP).flags == 0x14: # RST-ACK (0x14) or just RST (0x04)
                if verbose:
                    print(f"    [-] Port {port} on {target_ip} is CLOSED (SYN)")
        elif resp and resp.haslayer(ICMP):
            # ICMP errors (e.g., Type 3 Code 1, 2, 3, 9, 10, 13) often indicate filtered ports
            if resp.getlayer(ICMP).type == 3 and resp.getlayer(ICMP).code in [1,2,3,9,10,13]:
                if verbose:
                    print(f"    [-] Port {port} on {target_ip} is FILTERED (ICMP unreachable)")
        else:
            # No response often indicates filtered (dropped by firewall)
            if verbose:
                print(f"    [-] Port {port} on {target_ip} is FILTERED (No response/timeout)")

    except Exception as e:
        if verbose:
            print(f"    [!] SYN Scan Port {port} on {target_ip} error: {e}")

def worker_syn_scan_port(target_ip, ports_to_scan_queue, open_ports_queue, timeout, verbose):
    """
    Worker function for threads: picks a port from the queue, performs SYN scan, and puts result.
    """
    while True:
        try:
            port = ports_to_scan_queue.get(timeout=1)
            check_syn_port(target_ip, port, timeout, open_ports_queue, verbose)
            ports_to_scan_queue.task_done() # <--- Correct placement of task_done()
        except queue.Empty:
            break # No more ports to scan
        except Exception as e:
            # Handle unexpected errors in scan logic without crashing the worker
            if verbose:
                print(f"    [!] Error in SYN worker for {target_ip}: {e}")
def tcp_syn_scan_threaded(target_ip, ports, timeout=0.5, verbose=False):
    """
    Performs a TCP SYN scan on a single target IP for the given ports using multi-threading.
    Returns a list of open ports.
    """
    if verbose:
        print(f"[*] Starting TCP SYN scan for {target_ip} on {len(ports)} ports using {THREADS} threads...")

    ports_to_scan_queue = queue.Queue()
    open_ports_queue = queue.Queue()

    for port in ports:
        ports_to_scan_queue.put(port)

    threads = []
    for _ in range(THREADS):
        thread = threading.Thread(
            target=worker_syn_scan_port,
            args=(target_ip, ports_to_scan_queue, open_ports_queue, timeout, verbose)
        )
        thread.daemon = True
        thread.start()
        threads.append(thread)

    ports_to_scan_queue.join()

    # Give threads a moment to fully finish and clean up
    for thread in threads:
        if thread.is_alive():
            thread.join(timeout=0.1)
    
    # Collect results from the open_ports_queue
    discovered_open_ports = []
    while not open_ports_queue.empty():
        try:
            discovered_open_ports.append(open_ports_queue.get_nowait())
        except queue.Empty:
            break # Should not happen if empty check is correct, but safe

    if verbose:
        print(f"[*] TCP SYN scan for {target_ip} completed. Found {len(discovered_open_ports)} open ports.")

    return discovered_open_ports


def check_udp_port(target_ip, port, timeout, open_ports_queue, verbose):
    """
    Performs a UDP scan on a single port using Scapy.
    Due to UDP's nature, 'open' ports might not respond.
    A 'closed' port typically sends an ICMP Port Unreachable.
    No response generally means 'open|filtered'.
    """
    # Craft a basic UDP packet. The payload can be anything, often an empty one.
    # For more advanced scans, you'd send protocol-specific payloads (e.g., DNS query for port 53).
    udp_packet = IP(dst=target_ip)/UDP(dport=port, sport=5353) # Source port can be arbitrary

    try:
        # sr1 is good here too as we expect one ICMP response or none
        resp = sr1(udp_packet, timeout=timeout, verbose=False, retry=0)

        if resp is None:
            # No response: potentially open (no service response) or filtered by firewall
            open_ports_queue.put(port) # Treat as potentially open for now
            if verbose:
                print(f"    [+] Port {port}/UDP is OPEN|FILTERED (no response)")
        elif resp.haslayer(ICMP):
            # ICMP response: Check for 'Port Unreachable' (Type 3, Code 3)
            if resp.getlayer(ICMP).type == 3 and resp.getlayer(ICMP).code == 3:
                if verbose:
                    print(f"    [-] Port {port}/UDP is CLOSED (ICMP Port Unreachable)")
            else:
                # Other ICMP errors (e.g., host unreachable)
                if verbose:
                    print(f"    [-] Port {port}/UDP is FILTERED (ICMP Type {resp.getlayer(ICMP).type} Code {resp.getlayer(ICMP).code})")
        elif resp.haslayer(UDP):
            # We received a UDP response (e.g., DNS reply). This definitely means the port is open.
            open_ports_queue.put(port)
            if verbose:
                print(f"    [+] Port {port}/UDP is OPEN (received UDP response)")
        else:
            # Any other unexpected response
            if verbose:
                print(f"    [-] Port {port}/UDP unknown response (potentially filtered)")

    except Exception as e:
        if verbose:
            print(f"    [!] UDP Scan Port {port} on {target_ip} error: {e}")


def udp_scan_threaded(target_ip, ports, timeout=0.5, verbose=False):
    """
    Performs a UDP scan on a single target IP for the given ports using multi-threading.
    Returns a list of potentially open/filtered ports.
    """
    if verbose:
        print(f"[*] Starting UDP scan for {target_ip} on {len(ports)} ports using {THREADS} threads...")

    ports_to_scan_queue = queue.Queue()
    open_ports_queue = queue.Queue()

    for port in ports:
        ports_to_scan_queue.put(port)

    threads = []
    for _ in range(THREADS):
        thread = threading.Thread(
            target=worker_udp_scan_port,
            args=(target_ip, ports_to_scan_queue, open_ports_queue, timeout, verbose)
        )
        thread.daemon = True
        thread.start()
        threads.append(thread)

    ports_to_scan_queue.join()

    # Give threads a moment to fully finish and clean up
    for thread in threads:
        if thread.is_alive():
            thread.join(timeout=0.1)
    
    # Collect results from the open_ports_queue
    discovered_open_ports = []
    while not open_ports_queue.empty():
        try:
            discovered_open_ports.append(open_ports_queue.get_nowait())
        except queue.Empty:
            break # Should not happen if empty check is correct, but safe

    if verbose:
        print(f"[*] UDP scan for {target_ip} completed. Found {len(discovered_open_ports)} potentially open/filtered ports.")

    return discovered_open_ports

def worker_udp_scan_port(target_ip, ports_to_scan_queue, open_ports_queue, timeout, verbose):
    """
    Worker function for threads: picks a port from the queue, performs UDP scan, and puts result.
    """
    while True:
        try:
            port = ports_to_scan_queue.get(timeout=1) # Get a port from the queue
            check_udp_port(target_ip, port, timeout, open_ports_queue, verbose)
            ports_to_scan_queue.task_done() # <--- Move task_done() here
        except queue.Empty:
            break # No more ports to scan
        except Exception as e:
            # Handle unexpected errors in scan logic without crashing the worker
            if verbose:
                print(f"    [!] Error in UDP worker for {target_ip}: {e}")
            ports_to_scan_queue.task_done() # Still mark task done even on error, to avoid hanging join()

VULN_DB_PATH = "vulnerabilities.json" # Define the path to your vulnerability database

def load_vulnerability_database(file_path):
    """
    Loads the vulnerability database from a JSON file.
    """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Vulnerability database '{file_path}' not found. Skipping vulnerability analysis.")
        return {}
    except json.JSONDecodeError as e:
        print(f"[!] Error decoding vulnerability database '{file_path}': {e}. Skipping vulnerability analysis.")
        return {}
def get_service_banner(target_ip, port, protocol="tcp", timeout=1):
    """
    Attempts to grab a service banner from an open port.
    Returns a string with service info (e.g., "HTTP - Apache/2.4.41") or "Unknown".
    """
    service_info = "Unknown"

    if protocol.lower() == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((target_ip, port))

            # Send common probes depending on port
            if port in [80, 443, 8080, 8443]: # HTTP(S) ports
                sock.sendall(b"GET / HTTP/1.0\r\n\r\n") # Basic HTTP request
            elif port in [21]: # FTP
                sock.sendall(b"HELP\r\n") # FTP HELP command
            elif port in [25, 110, 143]: # SMTP, POP3, IMAP
                sock.sendall(b"HELO test.com\r\n") # Basic mail protocol HELO

            # Receive data (banner)
            banner = sock.recv(1024).decode(errors='ignore').strip() # Decode, ignore errors, remove whitespace

            if banner:
                # Basic banner parsing logic (can be expanded)
                if port in [80, 443, 8080, 8443]: # HTTP
                    if "Server:" in banner:
                        server_line = [line for line in banner.split('\n') if "Server:" in line]
                        if server_line:
                            service_info = "HTTP - " + server_line[0].split("Server:")[1].strip()
                        else:
                            service_info = "HTTP"
                    else:
                        service_info = "HTTP"
                elif port == 21: # FTP
                    service_info = "FTP - " + banner.split('\n')[0] # Often first line is banner
                elif port == 22: # SSH
                    service_info = "SSH - " + banner.split('\n')[0] # SSH banner is usually first line upon connect
                elif port == 23: # Telnet (often provides prompt, less a clear banner)
                    service_info = "Telnet"
                elif port == 25: # SMTP
                    service_info = "SMTP - " + banner.split('\n')[0]
                elif port == 110: # POP3
                    service_info = "POP3 - " + banner.split('\n')[0]
                elif port == 135: # RPC (often just connects)
                    service_info = "RPC"
                elif port == 3389: # RDP
                    service_info = "RDP"
                elif port == 445: # SMB
                    service_info = "SMB"
                else:
                    service_info = banner.split('\n')[0] if '\n' in banner else banner[:50] # Take first line or first 50 chars

        except socket.timeout:
            service_info = "No Banner (Timeout)"
        except ConnectionRefusedError:
            service_info = "No Banner (Connection Refused)" # Should not happen if port is OPEN
        except Exception as e:
            # print(f"DEBUG: Error grabbing banner for {target_ip}:{port} - {e}") # For debugging
            service_info = f"No Banner (Error: {type(e).__name__})"
        finally:
            sock.close()

    elif protocol.lower() == "udp":
        # UDP banner grabbing is more complex and usually involves protocol-specific queries.
        # For this basic implementation, we'll mark UDP services as "UDP Service"
        # In advanced scenarios, you'd send DNS queries to 53, NTP queries to 123, etc.
        if port == 53:
            service_info = "DNS (UDP)"
        elif port == 67 or port == 68:
            service_info = "DHCP (UDP)"
        elif port == 123:
            service_info = "NTP (UDP)"
        elif port == 161:
            service_info = "SNMP (UDP)"
        elif port == 514:
            service_info = "Syslog (UDP)"
        else:
            service_info = "UDP Service"

    return service_info
# ... (existing get_service_banner function) ...

def identify_vulnerabilities(service_name, service_version, vulnerability_db, verbose=False):
    """
    Looks up vulnerabilities for a given service and version in the loaded database.
    Returns a list of dictionaries, each containing 'cve_id' and 'description'.
    Handles basic version matching (e.g., "Apache/2.4.41" matches "2.4.x").
    """
    found_vulnerabilities = []

    # Normalize service name for lookup (lowercase)
    normalized_service_name = service_name.split(' ')[0].lower() # Take first word, make lowercase

    if normalized_service_name in vulnerability_db:
        service_vulns = vulnerability_db[normalized_service_name]

        # Extract major.minor or other relevant parts of version for matching
        # This is a simplified approach and can be expanded for more complex version schemes
        parsed_version = ""
        if service_version:
            # Try to get 'X.Y.Z' or 'X.Y' pattern
            version_match = re.match(r'(\d+\.\d+(\.\d+)?)', service_version) # Use regex for better matching
            if version_match:
                parsed_version = version_match.group(1)
            else:
                # Fallback for simpler versions like "2.3.4" directly from FTP example
                parsed_version = service_version.strip()

        if verbose:
            print(f"    [*] Checking vulnerabilities for '{normalized_service_name}' version '{service_version}' (parsed: '{parsed_version}')")


        for db_version_key, cve_list in service_vulns.items():
            # Basic matching logic:
            # 1. Exact match (e.g., "7.2p2" == "7.2p2")
            # 2. Wildcard match (e.g., "2.4.41" starts with "2.4." to match "2.4.x")
            # 3. Simple prefix match

            match_found = False
            if db_version_key.endswith('.x'): # Handle "X.Y.x" pattern
                prefix = db_version_key[:-2] # Get "X.Y."
                if parsed_version.startswith(prefix):
                    match_found = True
            elif db_version_key == parsed_version: # Exact version match
                match_found = True
            elif parsed_version.startswith(db_version_key): # Prefix match (e.g., db has "2.4", service is "2.4.41")
                match_found = True
            # Add more sophisticated version comparison here if needed (e.g., semver)

            if match_found:
                for cve in cve_list:
                    found_vulnerabilities.append(cve)
                    if verbose:
                        print(f"        [!] Potential Vulnerability: {cve['cve_id']} - {cve['description']}")

    return found_vulnerabilities


# ... (existing udp_scan_threaded and worker_udp_scan_port functions) ...

def save_report_txt(scan_results, output_file):
    """
    Saves the scan results to a text file in a human-readable format.
    """
    try:
        with open(output_file, 'w') as f:
            f.write("Network Scan and Vulnerability Report\n")
            f.write("=" * 40 + "\n\n")

            if not scan_results:
                f.write("No open ports found on active hosts.\n")
                return

            for host_ip, ports_data in scan_results.items():
                f.write(f"Host: {host_ip}\n")
                f.write("-" * (len(host_ip) + 6) + "\n") # Line under host

                if ports_data:
                    for port_detail in sorted(ports_data, key=lambda x: x['port']):
                        f.write(f"    Port {port_detail['port']}/{port_detail['protocol']} is OPEN -> {port_detail['service']}\n")
                        if port_detail['vulnerabilities']:
                            for vuln in port_detail['vulnerabilities']:
                                f.write(f"        [!!!] VULNERABILITY: {vuln['cve_id']} - {vuln['description']}\n")
                        else:
                            f.write("        (No specific vulnerabilities identified based on known database)\n")
                else:
                    f.write("    No open ports found on this host.\n")
                f.write("\n") # Newline between hosts

        console.print(f"[bold green][+][/bold green] Report saved to [bold cyan]{output_file}[/bold cyan] (Text Format)")
    except IOError as e:
        console.print(f"[bold red][!][/bold red] [red]Error saving text report to {output_file}: {e}[/red]")
        

# ... (existing save_report_txt function) ...

def save_report_csv(scan_results, output_file):
    """
    Saves the scan results to a CSV file. Each vulnerability gets its own row.
    """
    headers = ["IP Address", "Port", "Protocol", "Service", "Service Version", "CVE ID", "CVE Description"]
    try:
        with open(output_file, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(headers) # Write headers

            if not scan_results:
                # Write a row with empty data if no results, just headers
                csv_writer.writerow(["No open ports found", "", "", "", "", "", ""])
                return

            for host_ip, ports_data in scan_results.items():
                if ports_data:
                    for port_detail in sorted(ports_data, key=lambda x: x['port']):
                        # Extract service name and version from 'service' string for CSV
                        service_name_for_csv = port_detail['service']
                        service_version_for_csv = ""
                        match = re.search(r'([\d\.]+[a-zA-Z0-9\._-]*)', service_name_for_csv)
                        if match:
                            service_version_for_csv = match.group(0) # Get the matched version string
                            # Optionally, clean service_name_for_csv if it contains version
                            service_name_for_csv = service_name_for_csv.replace(service_version_for_csv, "").strip(" -")

                        if not port_detail['vulnerabilities']:
                            # If no vulnerabilities, write one row for the port
                            csv_writer.writerow([
                                host_ip,
                                port_detail['port'],
                                port_detail['protocol'],
                                service_name_for_csv,
                                service_version_for_csv,
                                "", # No CVE ID
                                ""  # No CVE Description
                            ])
                        else:
                            # If vulnerabilities, write a row for each vulnerability
                            for vuln in port_detail['vulnerabilities']:
                                csv_writer.writerow([
                                    host_ip,
                                    port_detail['port'],
                                    port_detail['protocol'],
                                    service_name_for_csv,
                                    service_version_for_csv,
                                    vuln['cve_id'],
                                    vuln['description']
                                ])
                else:
                    # If host found but no open ports
                    csv_writer.writerow([host_ip, "No Open Ports", "", "", "", "", ""])

        console.print(f"[bold green][+][/bold green] Report saved to [bold cyan]{output_file}[/bold cyan] (CSV Format)")
    except IOError as e:
        console.print(f"[bold red][!][/bold red] [red]Error saving CSV report to {output_file}: {e}[/red]")
    except Exception as e:
        console.print(f"[bold red][!][/bold red] [red]An unexpected error occurred while saving CSV: {e}[/red]")
def main():
    """
    Main function to run the network scanner.
    """
    args = parse_arguments()
    #--Load Vulnerability Database ---
    vulnerability_db = load_vulnerability_database(VULN_DB_PATH)
    if not vulnerability_db:
        print("[!] Could not load vulnerability database. Vulnerability analysis will be skipped.")
    #--- End Load Vulnerability Database ---
    print(f"[*] Starting network scan for target: {args.target}")
    if args.verbose:
        print("[*] Verbose mode enabled.")

    # --- Host Discovery Phase ---
    
    # 1. Parse target IP range into a list of individual IPs
    target_ips_list = get_ip_range_ips(args.target)
    if not target_ips_list:
        print("[!] No valid IPs to scan. Exiting.")
        return # Exit if no IPs were parsed

    # Use a set to store unique IPs from both scan types
    all_discovered_hosts = set() 

    #2.1 Perform ARP Scan
    print("[*] Performing Host Discovery (ARP Scan)...")
    # Make sure your arp_scan function includes `iface="wlan0"` inside it
    arp_discovered_hosts = arp_scan(target_ips_list, args.verbose)
    all_discovered_hosts.update(arp_discovered_hosts) # Add ARP results to the set

    #2.2 Perform ICMP Ping Scan
    print("[*] Performing Host Discovery (ICMP Ping Scan)...")
    icmp_discovered_hosts = icmp_ping_scan(target_ips_list, args.verbose)
    all_discovered_hosts.update(icmp_discovered_hosts) # Add ICMP results to the set

    # 3. Print combined discovered hosts
    if all_discovered_hosts:
        print("\n[+] All Discovered Active Hosts:")
        # Convert set to list and sort before printing
        for host in sorted(list(all_discovered_hosts), key=lambda ip: list(map(int, ip.split('.')))):
            print(f"    - {host}")
    else:
        print("\n[-] No active hosts found via ARP or ICMP scan.")
    # --- End Host Discovery Phase ---
    
    #4 --- Port Scanning Phase ---

# --- Port Scanning Phase ---
    print("\n[*] Starting Port Scanning Phase...")
    # Dictionary to store results: {IP: [list_of_port_dicts], ...}
    # Each port_dict will be like: {"port": 80, "protocol": "TCP", "service": "HTTP - Apache/2.4.41"}
    scan_results = {} 

    for host_ip in sorted(list(all_discovered_hosts), key=lambda ip: list(map(int, ip.split('.')))):
        # This list will temporarily hold {"port": num, "protocol": "TCP/UDP"}
        # before we enrich it with service info
        raw_open_ports_info = [] 
        
        # Determine which scan type to perform based on command-line arguments
        if args.tcp_connect:
            print(f"[!] Performing TCP Connect Scan for {host_ip}...")
            ports_found = tcp_connect_scan_threaded(host_ip, COMMON_PORTS, timeout=0.5, verbose=args.verbose)
            for p in ports_found:
                raw_open_ports_info.append({"port": p, "protocol": "TCP"})
        elif args.tcp_syn:
            print(f"[!] Performing TCP SYN Scan for {host_ip} (requires root)...")
            ports_found = tcp_syn_scan_threaded(host_ip, COMMON_PORTS, timeout=1, verbose=args.verbose)
            for p in ports_found:
                raw_open_ports_info.append({"port": p, "protocol": "TCP"})
        elif args.udp_scan:
            print(f"[!] Performing UDP Scan for {host_ip} (requires root)...")
            ports_found = udp_scan_threaded(host_ip, COMMON_UDP_PORTS, timeout=1, verbose=args.verbose)
            for p in ports_found:
                raw_open_ports_info.append({"port": p, "protocol": "UDP"})
        else:
            print(f"[!] No valid scan type selected for {host_ip}. Skipping port scan.")
            continue # Skip to next host_ip

        if raw_open_ports_info: # If any ports were found in the selected scan type
            scan_results[host_ip] = [] # Initialize a list for this host's detailed port info

            print(f"[*] Enumerating services for {host_ip}...")
        for port_info in raw_open_ports_info:
            port = port_info["port"]
            protocol = port_info["protocol"]

            service_banner_info = get_service_banner(host_ip, port, protocol.lower(), timeout=1)

            # Extract service name and version for vulnerability lookup
            # This is a simplified extraction; depends on the banner format.
            # Example: "HTTP - Apache/2.4.41" -> service_name="Apache", version="2.4.41"
            service_name = "Unknown"
            service_version = ""
            if " - " in service_banner_info:
                parts = service_banner_info.split(" - ")
                service_name_raw = parts[0].strip()
                # Try to extract version from the second part if available
                if len(parts) > 1:
                    version_part = parts[1].strip()
                    # Simple attempt to get version number, e.g., "Apache/2.4.41" -> "2.4.41"
                    version_match = re.search(r'([\d\.]+[a-zA-Z0-9\._-]*)', version_part)
                    if version_match:
                        service_version = version_match.group(1)
                    elif version_part: # If no explicit version number but there's text
                        service_version = version_part # Use the whole string as version

                # Map common service strings to normalized keys in vulnerability_db
                if "http" in service_name_raw.lower():
                    service_name = "apache" # Default to apache for HTTP banners
                    if "nginx" in service_name_raw.lower():
                        service_name = "nginx"
                elif "ftp" in service_name_raw.lower():
                    service_name = "ftp"
                    if "vsftpd" in service_name_raw.lower():
                        service_name = "ftp" # We map vsftpd to ftp category in our db
                elif "ssh" in service_name_raw.lower():
                    service_name = "openssh" # Map common SSH to openssh category
                elif "dns" in service_name_raw.lower():
                    service_name = "dns"
                else:
                    service_name = service_name_raw.lower() # Use raw name if not common

            elif service_banner_info == "DNS (UDP)": # Special case for our UDP mapping
                service_name = "dns"
                service_version = "" # No version for generic DNS UDP
            elif service_banner_info == "DHCP (UDP)":
                service_name = "dhcp" # (add 'dhcp' to your vulnerabilities.json if you want to track)
                service_version = ""
            # Add more specific mappings if needed

            # Identify vulnerabilities based on extracted service_name and service_version
            identified_vulnerabilities = []
            if vulnerability_db and service_name != "Unknown": # Only try if DB loaded and service identified
                # Pass the original service_banner_info for more context in parsing if needed
                identified_vulnerabilities = identify_vulnerabilities(
                    service_name, service_version, vulnerability_db, args.verbose
                )

            # Store the detailed port information including vulnerabilities
            scan_results[host_ip].append({
                "port": port,
                "protocol": protocol,
                "service": service_banner_info, # Keep the original banner info
                "vulnerabilities": identified_vulnerabilities # Add list of vulnerabilities
            })

    # --- Print Final Scan Results with Service Info and Vulnerabilities ---
    if scan_results:
        console.print(Panel("[bold green]Scan Results with Service and Vulnerability Information[/bold green]", expand=True, border_style="green"))

        for host_ip, ports_data in scan_results.items():
            host_panel_content = Table(box=None, show_header=False, show_lines=False, pad_edge=False)
            # host_panel_content.add_column("Key")
            # host_panel_content.add_column("Value")

            host_panel_content.add_row(f"[bold white]Host:[/bold white]", f"[bold yellow]{host_ip}[/bold yellow]")

            ports_table = Table(title="[bold underline]Open Ports[/bold underline]", style="cyan", border_style="dim white", show_header=True, header_style="bold magenta")
            ports_table.add_column("Port", justify="left", style="green")
            ports_table.add_column("Protocol", justify="left", style="blue")
            ports_table.add_column("Service", justify="left", style="white")
            ports_table.add_column("Vulnerabilities", justify="left", style="red")

            found_vulnerabilities_on_host = False

            for port_detail in sorted(ports_data, key=lambda x: x['port']):
                vuln_str = ""
                if port_detail['vulnerabilities']:
                    found_vulnerabilities_on_host = True
                    for vuln in port_detail['vulnerabilities']:
                        vuln_str += f"[red]CVE: {vuln['cve_id']}\n[/red][dim]{vuln['description']}[/dim]\n"
                    vuln_str = vuln_str.strip() # Remove trailing newline
                else:
                    vuln_str = "[dim](None identified)[/dim]"

                ports_table.add_row(
                    str(port_detail['port']),
                    port_detail['protocol'],
                    port_detail['service'],
                    vuln_str
                )

            # Add ports table to host panel content
            host_panel_content.add_row("", Padding(ports_table, (0, 4, 0, 0))) # Indent the table

            # Add a message if no vulns were found for this host
            if not found_vulnerabilities_on_host:
                host_panel_content.add_row("", "[dim]No specific vulnerabilities identified on this host based on known database.[/dim]", style="italic blue")

            console.print(Panel(host_panel_content, border_style="yellow", title_align="left", title=f"[bold yellow]Host: {host_ip}[/bold yellow]"))
            console.print("\n") # Add a newline between host panels for spacing

    else:
        console.print(Panel("[bold red]No open ports found on active hosts.[/bold red]", expand=True, border_style="red"))

    # --- End Port Scanning Phase ---
    # --- Report Generation Phase ---
    # Add the report generation block here:
    if args.output:
        if args.format == 'txt':
            save_report_txt(scan_results, args.output)
        elif args.format == 'csv':
            save_report_csv(scan_results, args.output)
        # Add elif for other formats like HTML later if needed
    # --- End Report Generation Phase ---
# ... (if __name__ == "__main__": block remains the same) ...
if __name__ == "__main__":
    # Check for root privileges early (still needed for ARP/ICMP, but not strictly for TCP connect)
    if sys.platform == "linux" and os.geteuid() != 0:
        print("[!] This script often requires root privileges to run (e.g., sudo python3 main.py).")
        print("    Raw socket operations (like ARP/ICMP scanning) usually need elevated permissions.")
        print("    TCP Connect scans might work without root, but initial host discovery needs it.")
        sys.exit(1)

    main()