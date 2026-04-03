from flask import Flask, render_template, jsonify, request
from threading import Thread
from collections import Counter
from storage import initialize_files, load_data, clear_all, PACKET_FILE, ALERT_FILE
from sniffer import start_sniffing

app = Flask(__name__)


# ─── Page routes ─────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    packets = load_data(PACKET_FILE)
    alerts  = load_data(ALERT_FILE)
    return render_template(
        "index.html",
        packets=packets[::-1],
        alerts=alerts[::-1]
    )


# ─── API routes ───────────────────────────────────────────────────────────────

@app.route("/api/data")
def api_data():
    """Returns latest packets and alerts as JSON (used by live dashboard)."""
    packets = load_data(PACKET_FILE)
    alerts  = load_data(ALERT_FILE)
    return jsonify({
        "packets": packets[::-1],
        "alerts":  alerts[::-1],
    })


@app.route("/api/stats")
def api_stats():
    """
    Returns summary statistics for the dashboard counters.
    Useful for interview demos — shows you thought about analytics.
    """
    packets = load_data(PACKET_FILE)
    alerts  = load_data(ALERT_FILE)

    protocol_counts = Counter(p.get("protocol", "Other") for p in packets)
    top_src_ips     = Counter(p.get("src_ip") for p in packets).most_common(5)
    alert_types     = Counter(a.get("type") for a in alerts)
    severity_counts = Counter(a.get("severity", "Medium") for a in alerts)

    return jsonify({
        "total_packets":    len(packets),
        "total_alerts":     len(alerts),
        "protocol_counts":  dict(protocol_counts),
        "top_src_ips":      top_src_ips,
        "alert_types":      dict(alert_types),
        "severity_counts":  dict(severity_counts),
    })


@app.route("/api/clear", methods=["POST"])
def api_clear():
    """Wipe all captured data (handy for live demos)."""
    clear_all()
    return jsonify({"status": "cleared"})


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    initialize_files()

    # Sniffer runs in a background daemon thread
    sniff_thread = Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    # Never run debug=True in a real deployment
    app.run(debug=False, host="0.0.0.0", port=5000)
