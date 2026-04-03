import json
import os
import threading

PACKET_FILE = "packets.json"
ALERT_FILE  = "alerts.json"

# One lock shared across all read-modify-write operations
# This prevents race conditions when the sniffer thread and Flask
# thread both try to write at the same time
_lock = threading.Lock()

MAX_PACKETS = 500
MAX_ALERTS  = 200


def initialize_files():
    """Create empty JSON files if they don't already exist."""
    for file_name in [PACKET_FILE, ALERT_FILE]:
        if not os.path.exists(file_name):
            with open(file_name, "w") as f:
                json.dump([], f)


def load_data(file_name):
    """Safely load a JSON list from disk."""
    try:
        with open(file_name, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def _save_data(file_name, data):
    """Write a JSON list to disk (internal — always call inside _lock)."""
    with open(file_name, "w") as f:
        json.dump(data, f, indent=2)


def append_packet(packet_data):
    """Thread-safe append of a packet record, capped at MAX_PACKETS."""
    with _lock:
        data = load_data(PACKET_FILE)
        data.append(packet_data)
        if len(data) > MAX_PACKETS:
            data = data[-MAX_PACKETS:]
        _save_data(PACKET_FILE, data)


def append_alert(alert_data):
    """Thread-safe append of an alert record, capped at MAX_ALERTS."""
    with _lock:
        data = load_data(ALERT_FILE)
        data.append(alert_data)
        if len(data) > MAX_ALERTS:
            data = data[-MAX_ALERTS:]
        _save_data(ALERT_FILE, data)


def clear_all():
    """Wipe both files (useful for testing)."""
    with _lock:
        _save_data(PACKET_FILE, [])
        _save_data(ALERT_FILE,  [])
