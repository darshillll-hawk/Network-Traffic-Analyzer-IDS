import os
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from datetime import datetime
from storage import append_packet
from detector import detect_suspicious_activity


def process_packet(packet):
    """Extract fields from each captured packet and pass to detector."""
    if IP not in packet:
        return  # Ignore non-IP packets (ARP, etc.)

    packet_info = {
        "time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip":   packet[IP].src,
        "dst_ip":   packet[IP].dst,
        "protocol": "Other",
        "src_port": None,
        "dst_port": None,
        "flags":    "",
        "size":     len(packet),       # packet size in bytes
        "info":     "",                # human-readable detail
    }

    if packet.haslayer(TCP):
        packet_info["protocol"] = "TCP"
        packet_info["src_port"] = packet[TCP].sport
        packet_info["dst_port"] = packet[TCP].dport
        # Decode TCP flags to a readable string e.g. "SA", "S", "F"
        packet_info["flags"]    = str(packet[TCP].flags)
        # Label well-known ports in the info field
        port = packet[TCP].dport
        if port == 80:
            packet_info["info"] = "HTTP"
        elif port == 443:
            packet_info["info"] = "HTTPS"
        elif port == 22:
            packet_info["info"] = "SSH"
        elif port == 21:
            packet_info["info"] = "FTP"

    elif packet.haslayer(UDP):
        packet_info["protocol"] = "UDP"
        packet_info["src_port"] = packet[UDP].sport
        packet_info["dst_port"] = packet[UDP].dport
        # Annotate DNS queries
        if packet.haslayer(DNS) and packet[DNS].qd:
            try:
                query = packet[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                packet_info["info"] = f"DNS Query: {query}"
            except Exception:
                packet_info["info"] = "DNS"

    elif packet.haslayer(ICMP):
        packet_info["protocol"] = "ICMP"
        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
        packet_info["info"] = icmp_types.get(packet[ICMP].type, f"Type {packet[ICMP].type}")

    append_packet(packet_info)
    detect_suspicious_activity(packet_info)


def start_sniffing():
    """
    Start packet capture.
    Set the SNIFF_IFACE environment variable to target a specific interface,
    e.g.:  export SNIFF_IFACE=eth0
    Leave unset to let Scapy auto-detect (works on most Linux/macOS systems).
    Note: requires root / administrator privileges.
    """
    iface = os.getenv("SNIFF_IFACE", None)
    print(f"[NTA-IDS] Starting packet capture on interface: {iface or 'auto'}")
    sniff(prn=process_packet, store=False, iface=iface)
