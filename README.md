# JA3 Fingerprint
This script uses the Scapy library to sniff network traffic and identify JA3 fingerprints of TLS client hello packets. The script utilizes a queue to hold packets, and the hashlib library to compute the JA3 fingerprint.

## Prerequisites
- Python 3
- Scapy
- Queue (part of the Python Standard Library)
- hashlib (part of the Python Standard Library)
## Installation
1. Clone the repository:
```
git clone https://github.com/berkantrl/JA3-fingerprint.git
```
2. Install the required libraries:
```
pip install scapy queue hashlib
```
## Usage
To run the script, use the following command:
```
python ja3_fingerprint.py
```
The script will begin sniffing network traffic and printing JA3 fingerprints for TLS client hello packets to the console.

## Notes
- The script must be run with privileges to capture network traffic (e.g., with sudo on Linux).
- The script may not work on all systems due to differences in network configuration and available interfaces.
- The script may produce false positives or negatives due to variations in TLS client hello packets.
