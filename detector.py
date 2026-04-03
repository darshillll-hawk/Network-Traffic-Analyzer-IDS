from collections import defaultdict
from datetime import datetime, timedelta
from storage import append_alert

# ─── Counters ────────────────────────────────────────────────────────────────
ip_packet_count  = defaultdict(int)          # total packets per src IP
ip_ports_seen    = defaultdict(set)          # unique dst ports per src IP
ip_syn_count     = defaultdict(int)          # SYN-only packets (brute-force)
ip_icmp_count    = defaultdict(int)          # ICMP packets (ping flood)
ip_dns_count     = defaultdict(int)          # DNS queries

# ─── Cooldown tracking (prevent alert spam) ───────────────────────────────────
# Structure: { (src_ip, alert_type): last_alert_datetime }
_last_alerted: dict = {}
COOLDOWN_SECONDS = 60   # same IP+type won't fire again for 60 s


# ─── Known suspicious destination ports ──────────────────────────────────────
SUSPICIOUS_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    135:  "MS-RPC",
    139:  "NetBIOS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    27017:"MongoDB",
}

# ─── Thresholds ───────────────────────────────────────────────────────────────
PACKET_FLOOD_THRESHOLD = 50   # packets from one IP before "flood" alert
PORT_SCAN_THRESHOLD    = 10   # unique ports before "port scan" alert
SYN_FLOOD_THRESHOLD    = 20   # SYN packets before "SYN flood" alert
ICMP_FLOOD_THRESHOLD   = 15   # ICMP packets before "ICMP flood" alert
DNS_BURST_THRESHOLD    = 25   # DNS queries before "DNS burst" alert


# ─── Helpers ─────────────────────────────────────────────────────────────────
def _now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _can_alert(src_ip: str, alert_type: str) -> bool:
    """Return True if cooldown has expired for this (ip, type) pair."""
    key = (src_ip, alert_type)
    last = _last_alerted.get(key)
    if last is None or datetime.now() - last > timedelta(seconds=COOLDOWN_SECONDS):
        _last_alerted[key] = datetime.now()
        return True
    return False


def _fire(src_ip: str, alert_type: str, message: str, severity: str = "Medium"):
    if _can_alert(src_ip, alert_type):
        append_alert({
            "time":     _now_str(),
            "type":     alert_type,
            "severity": severity,
            "message":  message,
        })


# ─── Main detection function ──────────────────────────────────────────────────
def detect_suspicious_activity(packet_info: dict):
    src_ip   = packet_info.get("src_ip", "Unknown")
    dst_ip   = packet_info.get("dst_ip", "Unknown")
    dst_port = packet_info.get("dst_port")
    protocol = packet_info.get("protocol", "Other")
    flags    = packet_info.get("flags", "")

    # 1. Track total packet volume ──────────────────────────────────────────
    ip_packet_count[src_ip] += 1
    if ip_packet_count[src_ip] >= PACKET_FLOOD_THRESHOLD:
        _fire(src_ip, "Traffic Flood",
              f"{src_ip} sent {ip_packet_count[src_ip]}+ packets — possible flood attack",
              severity="High")
        ip_packet_count[src_ip] = 0

    # 2. Port scan detection ────────────────────────────────────────────────
    if dst_port is not None:
        ip_ports_seen[src_ip].add(dst_port)
    if len(ip_ports_seen[src_ip]) >= PORT_SCAN_THRESHOLD:
        _fire(src_ip, "Port Scan Detected",
              f"{src_ip} probed {len(ip_ports_seen[src_ip])} unique ports — possible reconnaissance",
              severity="High")
        ip_ports_seen[src_ip].clear()

    # 3. Suspicious port access ─────────────────────────────────────────────
    if dst_port in SUSPICIOUS_PORTS:
        service = SUSPICIOUS_PORTS[dst_port]
        _fire(src_ip, "Suspicious Port Access",
              f"{src_ip} → {dst_ip}:{dst_port} ({service}) — sensitive service contacted",
              severity="Medium")

    # 4. SYN flood (TCP with only SYN flag) ─────────────────────────────────
    if protocol == "TCP" and flags == "S":
        ip_syn_count[src_ip] += 1
        if ip_syn_count[src_ip] >= SYN_FLOOD_THRESHOLD:
            _fire(src_ip, "SYN Flood Detected",
                  f"{src_ip} sent {ip_syn_count[src_ip]} SYN-only packets — possible DoS attempt",
                  severity="Critical")
            ip_syn_count[src_ip] = 0

    # 5. ICMP flood (ping flood) ─────────────────────────────────────────────
    if protocol == "ICMP":
        ip_icmp_count[src_ip] += 1
        if ip_icmp_count[src_ip] >= ICMP_FLOOD_THRESHOLD:
            _fire(src_ip, "ICMP Flood Detected",
                  f"{src_ip} sent {ip_icmp_count[src_ip]} ICMP packets — possible ping flood",
                  severity="High")
            ip_icmp_count[src_ip] = 0

    # 6. DNS burst detection ──────────────────────────────────────────────────
    if protocol == "UDP" and dst_port == 53:
        ip_dns_count[src_ip] += 1
        if ip_dns_count[src_ip] >= DNS_BURST_THRESHOLD:
            _fire(src_ip, "DNS Query Burst",
                  f"{src_ip} made {ip_dns_count[src_ip]} DNS queries — possible DNS tunneling or enumeration",
                  severity="Medium")
            ip_dns_count[src_ip] = 0
