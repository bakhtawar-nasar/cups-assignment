#!/usr/bin/env python3
"""
cups_detector.py - CUPS Attack Detection Tool
DAT510 - Network Security and Vulnerability
Detects suspicious CUPS/IPP network activity using Scapy.
Supports live monitoring and offline PCAP analysis.
"""

import argparse
import csv
import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime

from scapy.all import (
    IP, TCP, UDP, Raw,
    sniff, rdpcap, conf
)

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

# Port 631 is the standard port for CUPS and IPP (Internet Printing Protocol)
CUPS_PORT = 631

# If the same IP sends more than this many UDP announcements in a short time,
# it is flagged as suspicious (Repeated Discovery Attack)
REPEAT_THRESHOLD = 3

# List of IP addresses that are allowed to advertise printers.
# Any IP not in this list that sends a printer announcement will be flagged.
# Add your known legitimate printer IPs here.
ALLOWED_PRINTER_IPS = []

# Keywords that should NEVER appear in a legitimate printer announcement.
# Their presence means someone is trying to inject a command.
MALICIOUS_KEYWORDS = [
    b"FoomaticRIPCommandLine",
    b"cupsFilter2",
    b"foomatic-rip",
    b"I_AM_VULNERABLE",
    b"/bin/sh",
    b"/bin/bash",
    b"cmd.exe",
    b"wget ",
    b"curl ",
    b"chmod ",
    b"python",
    b"nc -",
    b"netcat",
]

# ─────────────────────────────────────────────
# ALERT SYSTEM
# ─────────────────────────────────────────────

alerts = []  # Stores all alerts generated during the session

def generate_alert(alert_type, severity, src_ip, dst_ip, details, packet_summary=""):
    """
    Creates a security alert and prints it to the screen.
    
    alert_type  : what kind of attack was detected
    severity    : HIGH, MEDIUM, or LOW
    src_ip      : the IP address the suspicious packet came FROM
    dst_ip      : the IP address the suspicious packet was sent TO
    details     : a plain-English description of what was detected
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = {
        "timestamp":      timestamp,
        "alert_type":     alert_type,
        "severity":       severity,
        "src_ip":         src_ip,
        "dst_ip":         dst_ip,
        "details":        details,
        "packet_summary": packet_summary,
    }

    alerts.append(alert)

    # Print the alert to screen with colour based on severity
    color = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}.get(severity, "")
    reset = "\033[0m"

    print(f"\n{color}[ALERT - {severity}] {timestamp}{reset}")
    print(f"  Type    : {alert_type}")
    print(f"  Source  : {src_ip}  →  Destination : {dst_ip}")
    print(f"  Details : {details}")
    if packet_summary:
        print(f"  Packet  : {packet_summary}")
    print("-" * 60)

    logging.warning(
        f"[{severity}] {alert_type} | {src_ip} -> {dst_ip} | {details}"
    )

# ─────────────────────────────────────────────
# DETECTION LOGIC
# ─────────────────────────────────────────────

# Keeps count of how many times each IP has sent a UDP announcement
announcement_count = defaultdict(int)

def detect_unauthorized_printer_advertisement(packet):
    """
    DETECTION 1 — Unauthorized Printer Advertisement (CVE-2024-47176)

    cups-browsed listens on UDP port 631 for printer announcements.
    Any machine on the network can send one of these announcements.
    This function flags announcements from IPs that are not in
    the ALLOWED_PRINTER_IPS list.
    """
    if not (UDP in packet and packet[UDP].dport == CUPS_PORT):
        return
    if not (IP in packet and Raw in packet):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    payload = packet[Raw].load

    # A CUPS browse packet looks like: "0x00 0x03 http://...printer..."
    # We check for common printer URL patterns in the UDP payload
    if b"http://" in payload or b"ipp://" in payload or b"/printers/" in payload:
        announcement_count[src_ip] += 1

        if ALLOWED_PRINTER_IPS and src_ip not in ALLOWED_PRINTER_IPS:
            generate_alert(
                alert_type     = "Unauthorized Printer Advertisement",
                severity       = "HIGH",
                src_ip         = src_ip,
                dst_ip         = dst_ip,
                details        = (
                    f"IP {src_ip} advertised a printer but is NOT in the "
                    f"allowed list. Payload preview: {payload[:80]}"
                ),
                packet_summary = packet.summary(),
            )
        else:
            # Even if the IP is allowed (or no allowlist is set),
            # still log it as LOW severity for visibility
            generate_alert(
                alert_type     = "Printer Advertisement Detected",
                severity       = "LOW",
                src_ip         = src_ip,
                dst_ip         = dst_ip,
                details        = (
                    f"IP {src_ip} sent a printer discovery announcement. "
                    f"Payload preview: {payload[:80]}"
                ),
                packet_summary = packet.summary(),
            )


def detect_repeated_discovery(packet):
    """
    DETECTION 2 — Repeated / Abnormal Discovery Messages (CVE-2024-47176)

    If the same IP sends many printer announcements in a short time,
    this is unusual and likely an automated attack tool.
    Normal printers do not spam announcements.
    """
    if not (UDP in packet and packet[UDP].dport == CUPS_PORT):
        return
    if not (IP in packet and Raw in packet):
        return

    src_ip  = packet[IP].src
    dst_ip  = packet[IP].dst
    payload = packet[Raw].load

    if b"http://" in payload or b"ipp://" in payload or b"/printers/" in payload:
        count = announcement_count[src_ip]  # already incremented in Detection 1

        if count == REPEAT_THRESHOLD:
            generate_alert(
                alert_type     = "Repeated Printer Discovery Messages",
                severity       = "MEDIUM",
                src_ip         = src_ip,
                dst_ip         = dst_ip,
                details        = (
                    f"IP {src_ip} has sent {count} printer announcements. "
                    f"Threshold is {REPEAT_THRESHOLD}. This may be an "
                    f"automated attack tool."
                ),
                packet_summary = packet.summary(),
            )
        elif count > REPEAT_THRESHOLD:
            generate_alert(
                alert_type     = "Repeated Printer Discovery Messages",
                severity       = "HIGH",
                src_ip         = src_ip,
                dst_ip         = dst_ip,
                details        = (
                    f"IP {src_ip} has now sent {count} printer announcements "
                    f"(threshold: {REPEAT_THRESHOLD}). Likely attack in progress."
                ),
                packet_summary = packet.summary(),
            )


def detect_suspicious_ipp_connection(packet):
    """
    DETECTION 3 — Suspicious IPP Connection (CVE-2024-47076)

    After cups-browsed receives a fake printer announcement, it connects
    back to the attacker's machine using TCP on whatever port was advertised.
    This function watches for outgoing TCP connections FROM the CUPS server
    to unexpected destinations — which means the victim is connecting to
    an attacker-controlled printer.
    """
    if not (TCP in packet and IP in packet):
        return

    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    dst_port = packet[TCP].dport
    flags    = packet[TCP].flags

    # SYN flag means this is the START of a new TCP connection
    # (SYN = Synchronise, the first step in TCP's three-way handshake,
    # which is the process of establishing a TCP connection)
    is_syn = flags == 0x002  # SYN only, not SYN-ACK

    # Flag outgoing connections to non-standard IPP ports
    # Port 631 is standard; connections to other ports like 12345
    # (used by the evil-ipp-server) are suspicious
    if is_syn and dst_port not in (631, 80, 443):
        if Raw in packet:
            payload = packet[Raw].load
            if b"ipp" in payload.lower() or b"printer" in payload.lower():
                generate_alert(
                    alert_type     = "Suspicious IPP Connection",
                    severity       = "HIGH",
                    src_ip         = src_ip,
                    dst_ip         = dst_ip,
                    details        = (
                        f"TCP connection to non-standard port {dst_port} "
                        f"with IPP-related content. May indicate CUPS "
                        f"connecting to a malicious printer."
                    ),
                    packet_summary = packet.summary(),
                )

    # Also flag any TCP connection on port 631 from an IP not in the allowed list
    if is_syn and dst_port == CUPS_PORT:
        if ALLOWED_PRINTER_IPS and src_ip not in ALLOWED_PRINTER_IPS:
            generate_alert(
                alert_type     = "Unauthorized IPP Connection Attempt",
                severity       = "MEDIUM",
                src_ip         = src_ip,
                dst_ip         = dst_ip,
                details        = (
                    f"TCP SYN to CUPS port 631 from {src_ip}, "
                    f"which is NOT in the allowed list."
                ),
                packet_summary = packet.summary(),
            )


def detect_malformed_fields(packet):
    """
    DETECTION 4 — Malformed or Unexpected Protocol Fields (CVE-2024-47175)

    The evil-ipp-server injects commands into the printer-privacy-policy-uri
    field. This function scans all packet payloads for known malicious
    keywords that should NEVER appear in legitimate printer traffic.

    Keywords like FoomaticRIPCommandLine, foomatic-rip, /bin/sh are
    signs of a command injection attempt.
    """
    if not (IP in packet and Raw in packet):
        return

    src_ip  = packet[IP].src
    dst_ip  = packet[IP].dst
    payload = packet[Raw].load

    for keyword in MALICIOUS_KEYWORDS:
        if keyword.lower() in payload.lower():
            generate_alert(
                alert_type     = "Malformed / Suspicious Protocol Field",
                severity       = "HIGH",
                src_ip         = src_ip,
                dst_ip         = dst_ip,
                details        = (
                    f"Packet contains suspicious keyword: '{keyword.decode(errors='replace')}'. "
                    f"This may indicate a command injection attempt via "
                    f"a crafted IPP printer attribute (CVE-2024-47175)."
                ),
                packet_summary = packet.summary(),
            )
            break  # One alert per packet is enough


# ─────────────────────────────────────────────
# PACKET PROCESSOR
# ─────────────────────────────────────────────

def process_packet(packet):
    """
    This function is called for EVERY packet, whether live or from a PCAP file.
    It runs all four detection checks on each packet.
    """
    detect_unauthorized_printer_advertisement(packet)
    detect_repeated_discovery(packet)
    detect_suspicious_ipp_connection(packet)
    detect_malformed_fields(packet)


# ─────────────────────────────────────────────
# EXPORT RESULTS
# ─────────────────────────────────────────────

def export_results(output_file, fmt):
    """
    Saves all generated alerts to a file.
    fmt = "csv"  → saves as a CSV file (comma-separated values, opens in Excel)
    fmt = "json" → saves as a JSON file (JavaScript Object Notation,
                   a standard structured data format)
    """
    if not alerts:
        print("\n[INFO] No alerts to export.")
        return

    if fmt == "csv":
        path = output_file if output_file.endswith(".csv") else output_file + ".csv"
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
            writer.writeheader()
            writer.writerows(alerts)
        print(f"\n[+] Exported {len(alerts)} alerts to {path}")

    elif fmt == "json":
        path = output_file if output_file.endswith(".json") else output_file + ".json"
        with open(path, "w") as f:
            json.dump(alerts, f, indent=2)
        print(f"\n[+] Exported {len(alerts)} alerts to {path}")


# ─────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────

def print_summary():
    """Prints a short summary at the end of the session."""
    print("\n" + "=" * 60)
    print("  DETECTION SUMMARY")
    print("=" * 60)
    print(f"  Total alerts generated : {len(alerts)}")

    if alerts:
        high   = sum(1 for a in alerts if a["severity"] == "HIGH")
        medium = sum(1 for a in alerts if a["severity"] == "MEDIUM")
        low    = sum(1 for a in alerts if a["severity"] == "LOW")
        print(f"  HIGH   : {high}")
        print(f"  MEDIUM : {medium}")
        print(f"  LOW    : {low}")

        print("\n  Alert types detected:")
        types = {}
        for a in alerts:
            types[a["alert_type"]] = types.get(a["alert_type"], 0) + 1
        for t, count in types.items():
            print(f"    - {t}: {count}")
    print("=" * 60)


# ─────────────────────────────────────────────
# MAIN — COMMAND LINE INTERFACE
# ─────────────────────────────────────────────

def main():
    global ALLOWED_PRINTER_IPS, REPEAT_THRESHOLD
    parser = argparse.ArgumentParser(
        description="CUPS Attack Detection Tool — detects suspicious CUPS/IPP network activity"
    )

    # How to run: live mode or offline PCAP mode
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "-i", "--interface",
        help="Network interface for LIVE monitoring (e.g. eth0)"
    )
    mode.add_argument(
        "-r", "--read",
        help="Path to a PCAP file for OFFLINE analysis (e.g. attack_traffic.pcap)"
    )

    # Optional arguments
    parser.add_argument(
        "-o", "--output",
        default="cups_alerts",
        help="Output file name for exported alerts (default: cups_alerts)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["csv", "json"],
        default="json",
        help="Export format: csv or json (default: json)"
    )
    parser.add_argument(
        "-a", "--allow",
        nargs="*",
        default=[],
        help="Allowed printer IP addresses (e.g. -a 192.168.1.10 192.168.1.11)"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=REPEAT_THRESHOLD,
        help=f"Number of announcements before flagging as repeated attack (default: {REPEAT_THRESHOLD})"
    )
    parser.add_argument(
        "-l", "--log",
        default="cups_detector.log",
        help="Log file path (default: cups_detector.log)"
    )

    args = parser.parse_args()

    # Apply command-line settings
    ALLOWED_PRINTER_IPS = args.allow
    REPEAT_THRESHOLD    = args.threshold

    # Set up logging to file
    logging.basicConfig(
        filename = args.log,
        level    = logging.WARNING,
        format   = "%(asctime)s %(levelname)s %(message)s",
    )

    print("=" * 60)
    print("  CUPS ATTACK DETECTOR — cups_detector.py")
    print("  DAT510 Network Security and Vulnerability")
    print("=" * 60)
    print(f"  Allowed printer IPs : {ALLOWED_PRINTER_IPS if ALLOWED_PRINTER_IPS else 'None set (all flagged as LOW)'}")
    print(f"  Repeat threshold    : {REPEAT_THRESHOLD} announcements")
    print(f"  Export format       : {args.format}")
    print(f"  Log file            : {args.log}")
    print("=" * 60)

    try:
        if args.interface:
            # LIVE MODE — capture packets in real time from a network interface
            print(f"\n[*] Starting LIVE monitoring on interface: {args.interface}")
            print("[*] Press Ctrl+C to stop.\n")
            sniff(
                iface   = args.interface,
                prn     = process_packet,
                store   = False,   # don't keep packets in memory
                filter  = f"port {CUPS_PORT} or port 12345",
            )

        elif args.read:
            # OFFLINE MODE — read packets from a saved PCAP file
            if not os.path.exists(args.read):
                print(f"[ERROR] File not found: {args.read}")
                sys.exit(1)

            print(f"\n[*] Analysing PCAP file: {args.read}\n")
            packets = rdpcap(args.read)
            print(f"[*] Loaded {len(packets)} packets. Running detection...\n")

            for packet in packets:
                process_packet(packet)

            print(f"\n[*] Analysis complete.")

    except KeyboardInterrupt:
        print("\n\n[*] Stopped by user.")

    finally:
        print_summary()
        export_results(args.output, args.format)
        print(f"\n[*] Log saved to: {args.log}")


if __name__ == "__main__":
    main()