# CUPS Printer Discovery Exploitation and Attack Detection

DAT510 — Network Security and Vulnerability  
University of Stavanger

## Vulnerabilities
- CVE-2024-47176 — cups-browsed accepts printer announcements from anyone
- CVE-2024-47076 — no validation of data received from fake printer
- CVE-2024-47175 — malicious data injected into PPD configuration file

## Files
- `cups_attack.py` — Scapy-based attack tool (printer discovery packets)
- `cups_detector.py` — Scapy-based detection tool
- `evil-ipp-server/poc.py` — IPP server used as fake printer
- `pcap_files/` — captured network traffic
- `evidence/` — screenshots and logs

## Setup
pip install -r requirements.txt


## Usage

**Attack tool:**

sudo python3 cups_attack.py -t 127.0.0.1 -a 172.30.28.54 --mode all --listen


**Detection tool (live):**

sudo python3 cups_detector.py -i eth0


**Detection tool (offline):**

python3 cups_detector.py -r pcap_files/attack_traffic.pcap -f json

## Environment
- Attacker: Ubuntu WSL2
- Victim: Vulhub cups-browsed:2.0.1 Docker container
- Python 3, Scapy 2.8.0

## Disclaimer
For educational use only in isolated lab environments.