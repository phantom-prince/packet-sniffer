# Packet Sniffer (Educational Use Only)
A Python-based network packet sniffer using Scapy.

## Requirements
- Python 3.12+
- Scapy (`pip install scapy`)
- Npcap (Windows)

## Usage
```bash
python packet_sniffer.py -l  # List interfaces
python packet_sniffer.py -i "Wi-Fi" -f "tcp port 80" -c 10  # Capture HTTP traffic
