from scapy.all import IP, TCP, UDP, ICMP, sniff, conf
import argparse
from datetime import datetime
import os
import ctypes

def get_windows_interfaces():
    """Get available network interfaces on Windows"""
    print("\nAvailable Interfaces:")
    try:
        for idx, iface in enumerate(conf.ifaces.values()):
            print(f"{idx + 1}. {iface.name} - {iface.description}")
    except Exception as e:
        print(f"Scapy interface error: {e}")
        print("\nWindows Network Interfaces:")
        os.system('netsh interface show interface')

def packet_handler(packet):
    """Process and display information about captured packets"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    protocol = src_ip = dst_ip = src_port = dst_port = payload = "N/A"
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            if packet[TCP].payload:
                payload = str(packet[TCP].payload)[:100]  
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            if packet[UDP].payload:
                payload = str(packet[UDP].payload)[:100]
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = packet[IP].proto
    
    print(f"\n[+] {timestamp} - Packet Captured")
    print(f"    Protocol: {protocol}")
    print(f"    Source: {src_ip}:{src_port}")
    print(f"    Destination: {dst_ip}:{dst_port}")
    
    if payload != "N/A":
        print(f"    Payload (first 100 bytes): {payload}")
    
    print("-" * 60)

def main():
    """Main function to handle arguments and start sniffing"""
    parser = argparse.ArgumentParser(
        description="Windows Packet Sniffer - For Educational Purposes Only",
        epilog="WARNING: Use only on networks you have permission to monitor."
    )
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", default=None)
    parser.add_argument("-l", "--list", help="List available interfaces", action="store_true")
    parser.add_argument("-c", "--count", help="Number of packets to capture (0 for unlimited)", type=int, default=0)
    parser.add_argument("-f", "--filter", help="BPF filter to apply", default="")
    
    args = parser.parse_args()
    
    print("\n" + "="*80)
    print("WINDOWS PACKET SNIFFER - FOR EDUCATIONAL PURPOSES ONLY")
    print("="*80)
    print("WARNING: Unauthorized network monitoring may violate privacy laws and")
    print("organizational policies. Use this tool only on networks you own or")
    print("have explicit permission to monitor.")
    print("="*80 + "\n")
    
    try:
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] Warning: Not running as administrator. Some packets may not be captured.")
            print("    Consider running this script as Administrator for best results.\n")
    except:
        pass
    
    if args.list:
        get_windows_interfaces()
        return
    
    try:
        print(f"[*] Starting packet capture on interface {args.interface or 'default'}")
        print(f"[*] Filter: {args.filter or 'None'}")
        print("[*] Press Ctrl+C to stop\n")
        
        sniff(
            iface=args.interface,
            prn=packet_handler,
            count=args.count,
            filter=args.filter,
            store=0
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
    except Exception as e:
        print(f"[!] Error: {e}")
        if "No such device" in str(e):
            print("[!] Try listing available interfaces with -l option")

if __name__ == "__main__":
    main()