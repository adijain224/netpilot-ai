"""
NetPilot AI — Intelligent Bandwidth Optimization & Resource Management
=======================================================================
Flask backend coordinating live network monitoring, device discovery,
explainable traffic classification, dynamic knowledge-graph generation,
predictive traffic forecasting, Q-learning allocation, and QoS enforcement.
"""

import os
import platform
import random
import threading
import time
from collections import deque
from typing import Dict, Any, List

from flask import Flask, jsonify, request, render_template

# NetPilot Modular Engine Components
from config import (
    CONFIG,
    DEFAULT_CONFIG,
    TRAFFIC_CATEGORIES,
    TRAFFIC_CSV,
    validate_capacity,
    validate_ip,
    validate_rate_limit,
    get_system_gateways_and_local_ips,
)
from traffic_classifier import global_classifier
from device_discovery import global_device_tracker, resolve_hostname, ping_host
from network_monitor import global_monitor, SCAPY_AVAILABLE
from allocation_engine import global_allocation_engine
from qos_controller import global_qos_controller
from traffic_predictor import global_predictor
from knowledge_graph import global_knowledge_graph
from evaluation import run_comparative_experiment

IS_WINDOWS = platform.system() == "Windows"
DEMO_MODE_ENV = os.environ.get("DEMO_MODE")

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

# --------------------------------------------------------------------------
# Global Synchronized Application State
# --------------------------------------------------------------------------
STATE_LOCK = threading.Lock()
STATE = {
    "started_at": time.time(),
    "interface": None,
    "data_mode": "measured-total / measured-per-device",
    "up_mbps": 0.0,
    "down_mbps": 0.0,
    "devices": {},
    "upstream_devices": [],
    "history": deque(maxlen=150),
    "decision_log": deque(maxlen=40),
    "graph": {"nodes": [], "edges": []},
    "allocation": {},
    "congestion": "low",
    "avg_latency": None,
    "demo_mode": DEMO_MODE_ENV == "1",
}


def format_bytes(num_bytes: int) -> str:
    """Format bytes into readable string (KB, MB, GB)."""
    n = float(num_bytes or 0)
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def background_control_loop():
    """
    Main NetPilot AI control loop executing periodically:
    Sense -> Discover -> Classify -> Allocate -> Predict -> Enforce -> Persist
    """
    tick = 0
    while True:
        tick += 1
        cfg = CONFIG
        iface = cfg.get("interface") or global_monitor.detect_primary_interface()

        with STATE_LOCK:
            STATE["interface"] = iface

        # 1. Sense physical link throughput (real OS hardware counters)
        up_mbps, down_mbps = global_monitor.get_link_throughput(iface)

        # In rehearsal/demo mode when link is completely idle, synthesize gentle test flow
        demo_active = cfg.get("demo_mode") or DEMO_MODE_ENV == "1"
        if demo_active and up_mbps < 0.05 and down_mbps < 0.05:
            wobble = random.Random(tick // 2)
            down_mbps = round(cfg["capacity_mbps"] * wobble.uniform(0.25, 0.65), 2)
            up_mbps = round(down_mbps * wobble.uniform(0.08, 0.22), 2)

        # 2. Discover devices (subnet-aware, excluding gateways and local host IPs)
        observed_packet_ips = global_monitor.get_observed_packet_ips()
        devices = global_device_tracker.scan_network(
            demo_mode=demo_active,
            tick=tick,
            observed_packet_ips=observed_packet_ips,
        )

        # 3. Pull differential per-device packet traffic and cumulative stats
        traffic_snapshot = global_monitor.get_device_traffic_snapshot(client_ips=list(devices.keys()))
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        csv_rows = []

        for ip, d in devices.items():
            stat = traffic_snapshot.get(
                ip,
                {"download_mbps": 0.0, "upload_mbps": 0.0, "total_rx_bytes": 0, "total_tx_bytes": 0, "total_packets": 0, "recent_ports": []}
            )

            # If simulation mode with no packets, assign proportional simulated usage
            if demo_active and stat["total_rx_bytes"] == 0:
                p_rnd = random.Random(hash(ip) + tick // 4)
                sim_down = round(p_rnd.uniform(0.5, 6.5), 2)
                sim_up = round(sim_down * 0.15, 2)
                stat["download_mbps"] = sim_down
                stat["upload_mbps"] = sim_up
                stat["total_rx_bytes"] = int(sim_down * 125_000 * tick)
                stat["total_tx_bytes"] = int(sim_up * 125_000 * tick)
                stat["total_packets"] = int(sim_down * 120 * tick)

            d["download_mbps"] = stat["download_mbps"]
            d["upload_mbps"] = stat["upload_mbps"]
            d["total_rx_bytes"] = stat["total_rx_bytes"]
            d["total_tx_bytes"] = stat["total_tx_bytes"]
            d["total_packets"] = stat["total_packets"]
            d["packets"] = stat["total_packets"]
            d["used_mbps"] = d["download_mbps"]
            d["total_rx_str"] = format_bytes(stat["total_rx_bytes"])
            d["total_tx_str"] = format_bytes(stat["total_tx_bytes"])
            d["total_data_str"] = format_bytes(stat["total_rx_bytes"] + stat["total_tx_bytes"])

            # Classify device traffic flow
            classification = global_classifier.classify_device_traffic(
                ip, d.get("hostname", ""), stat.get("recent_ports")
            )
            d["category"] = classification["category"]
            d["qos_class"] = classification.get("qos_class", "Interactive Web & Cloud")
            d["qos_icon"] = classification.get("qos_icon", "🌐")
            d["traffic_service"] = classification.get("service", "Unknown")
            d["classification_confidence"] = classification.get("confidence", 0.0)
            d["classification_reason"] = classification.get("reason", "")
            d["recent_domain"] = classification.get("recent_domain")

            csv_rows.append({
                "Device": d.get("hostname") or ip,
                "Download Mbps": d["download_mbps"],
                "Upload Mbps": d["upload_mbps"],
                "Packets": d["packets"],
                "Total Rx Bytes": d["total_rx_bytes"],
                "Total Tx Bytes": d["total_tx_bytes"],
                "Latency": "" if d.get("latency_ms") is None else round(d["latency_ms"], 1),
                "Timestamp": timestamp,
            })

        # Save history to CSV
        global_monitor.append_history(csv_rows)

        # 4. Latency averaging
        active_latencies = [d["latency_ms"] for d in devices.values() if d.get("latency_ms") is not None]
        avg_latency = round(sum(active_latencies) / len(active_latencies), 1) if active_latencies else None

        # 5. Compute AI Bandwidth Allocation
        global_allocation_engine.capacity_mbps = float(cfg["capacity_mbps"])
        allocation_res = global_allocation_engine.compute_allocation(
            devices=devices,
            total_used_mbps=down_mbps,
            avg_latency_ms=avg_latency,
        )

        for ip, d in devices.items():
            d["allocated_mbps"] = allocation_res["allocations"].get(ip, 0.0)
            d["allocation_reason"] = allocation_res["explanations"].get(ip, "")

        # 6. Apply QoS Enforcement if configured (dry-run or real)
        if global_qos_controller.mode != "simulation" and global_qos_controller.admin_authorized:
            for ip, rate in allocation_res["allocations"].items():
                if rate > 0 and devices.get(ip, {}).get("online"):
                    global_qos_controller.enforce_bandwidth_limit(ip, rate)

        # 7. Update Knowledge Graph (including Upstream Providers and Clients)
        upstream_devs = global_device_tracker.get_upstream_devices()
        graph_data = global_knowledge_graph.build_graph(
            interface_name=iface,
            devices=devices,
            allocation_data=allocation_res,
            congestion=allocation_res["congestion"],
            capacity_mbps=cfg["capacity_mbps"],
            upstream_devices=upstream_devs,
        )

        # 8. Record synchronized state updates
        with STATE_LOCK:
            STATE["up_mbps"] = round(up_mbps, 2)
            STATE["down_mbps"] = round(down_mbps, 2)
            STATE["devices"] = devices
            STATE["upstream_devices"] = upstream_devs
            STATE["history"].append({
                "t": time.time(),
                "up": STATE["up_mbps"],
                "down": STATE["down_mbps"],
            })
            STATE["allocation"] = allocation_res["allocations"]
            STATE["allocation_meta"] = allocation_res
            STATE["congestion"] = allocation_res["congestion"]
            STATE["avg_latency"] = avg_latency
            STATE["graph"] = graph_data
            STATE["demo_mode"] = demo_active

            # Append newest decision log entry
            if global_allocation_engine.decision_log:
                latest = global_allocation_engine.decision_log[0]
                STATE["decision_log"].appendleft({
                    "t": latest["t"],
                    "bucket": latest["congestion"],
                    "text": (
                        f"[{latest['congestion'].upper()}] Reward={latest['reward']:.2f} · "
                        f"Jain's={latest['jains_fairness']} · {latest['action']}"
                    ),
                })

        time.sleep(cfg["poll_seconds"])


# --------------------------------------------------------------------------
# Web & REST API Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    with STATE_LOCK:
        devices = STATE["devices"]
        online_count = sum(1 for d in devices.values() if d.get("online"))
        active_confirmed = sum(1 for d in devices.values() if d.get("status") == "confirmed_active")

        qos_status = global_qos_controller.get_status()

        return jsonify({
            "interface": STATE["interface"],
            "up_mbps": STATE["up_mbps"],
            "down_mbps": STATE["down_mbps"],
            "capacity_mbps": CONFIG["capacity_mbps"],
            "congestion": STATE.get("congestion", "low"),
            "avg_latency": STATE.get("avg_latency"),
            "device_count": len(devices),
            "online_count": online_count,
            "confirmed_active_count": active_confirmed,
            "upstream_count": len(STATE.get("upstream_devices", [])),
            "blocked_count": len(global_device_tracker.blocked_ips),
            "data_mode": STATE["data_mode"],
            "demo_mode": STATE.get("demo_mode", False),
            "uptime_s": round(time.time() - STATE["started_at"]),
            "scapy_available": SCAPY_AVAILABLE,
            "capture_status": global_monitor.capture_status["status"],
            "capture_interface": global_monitor.capture_status["interface"],
            "capture_error": global_monitor.capture_status["error"],
            "packets_captured": global_monitor.capture_status["packets_captured"],
            "traffic_csv": TRAFFIC_CSV,
            "qos_mode": qos_status["mode"],
            "qos_admin_authorized": qos_status["admin_authorized"],
            "is_simulation": qos_status["is_simulation"],
        })


@app.route("/api/devices")
def api_devices():
    with STATE_LOCK:
        return jsonify(list(STATE["devices"].values()))


@app.route("/api/diagnostics")
def api_diagnostics():
    """Returns detailed network topology diagnostics, gateway exclusion reasons, and capture health."""
    diag = global_device_tracker.get_diagnostics()
    diag["capture_status"] = global_monitor.capture_status
    diag["primary_interface"] = global_monitor.detect_primary_interface()
    diag["capture_interface"] = global_monitor.detect_capture_interface_name()
    diag["interfaces"] = global_monitor.get_available_interfaces()
    return jsonify(diag)


@app.route("/api/device/priority", methods=["POST"])
def api_device_priority():
    """Update priority for a specific device."""
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip")
    priority = data.get("priority")

    valid_ip, ip_clean = validate_ip(ip)
    if not valid_ip:
        return jsonify({"success": False, "error": f"Invalid IP address: {ip_clean}"}), 400

    if priority not in ("High", "Normal", "Low"):
        return jsonify({"success": False, "error": "Priority must be High, Normal, or Low."}), 400

    success = global_device_tracker.set_priority(ip_clean, priority)
    return jsonify({"success": success, "ip": ip_clean, "priority": priority})


@app.route("/api/device/block", methods=["POST"])
def api_device_block():
    """Completely cut off or restore Internet access for a specific client device."""
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip")
    blocked = bool(data.get("blocked", True))

    valid_ip, ip_clean = validate_ip(ip)
    if not valid_ip:
        return jsonify({"success": False, "error": f"Invalid IP address: {ip_clean}"}), 400

    global_device_tracker.block_device(ip_clean, blocked)
    if blocked:
        res = global_qos_controller.block_device(ip_clean)
        log_action = f"[ADMIN] Cut off all Internet access for {ip_clean} (Dropped to 0 Mbps instantly)"
    else:
        res = global_qos_controller.unblock_device(ip_clean)
        log_action = f"[ADMIN] Restored Internet access for {ip_clean}"

    with STATE_LOCK:
        if ip_clean in STATE["devices"]:
            STATE["devices"][ip_clean]["blocked"] = blocked
            if blocked:
                STATE["devices"][ip_clean]["status"] = "blocked"
                STATE["devices"][ip_clean]["allocated_mbps"] = 0.0
                STATE["devices"][ip_clean]["download_mbps"] = 0.0
                STATE["devices"][ip_clean]["upload_mbps"] = 0.0
                STATE["devices"][ip_clean]["used_mbps"] = 0.0
                STATE["devices"][ip_clean]["allocation_reason"] = "🚫 Internet access blocked by administrator (Traffic Cut-Off)."

        if "allocation" in STATE and ip_clean in STATE["allocation"]:
            STATE["allocation"][ip_clean] = 0.0

        # Recalculate AI allocations immediately across all devices so frontend reflects 0 Mbps instantly
        allocation_res = global_allocation_engine.compute_allocation(
            devices=STATE["devices"],
            total_used_mbps=STATE.get("down_mbps", 0.0),
            avg_latency_ms=STATE.get("avg_latency"),
        )
        STATE["allocation"] = allocation_res["allocations"]
        STATE["allocation_meta"] = allocation_res

        STATE["decision_log"].appendleft({
            "t": time.time(),
            "bucket": "high" if blocked else "low",
            "text": log_action,
        })

    return jsonify({
        "success": True,
        "ip": ip_clean,
        "blocked": blocked,
        "allocated_mbps": 0.0 if blocked else STATE.get("allocation", {}).get(ip_clean, 0.5),
        "qos_result": res
    })


@app.route("/api/device/role", methods=["POST"])
def api_device_role():
    """Switch device role between 'client' and 'upstream' (internet source/gateway)."""
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip")
    role = data.get("role", "client")

    valid_ip, ip_clean = validate_ip(ip)
    if not valid_ip:
        return jsonify({"success": False, "error": f"Invalid IP address: {ip_clean}"}), 400

    if role not in ("client", "upstream"):
        return jsonify({"success": False, "error": "Role must be 'client' or 'upstream'."}), 400

    global_device_tracker.set_device_role(ip_clean, role)
    with STATE_LOCK:
        STATE["upstream_devices"] = global_device_tracker.get_upstream_devices()
        STATE["decision_log"].appendleft({
            "t": time.time(),
            "bucket": "low",
            "text": f"[ROLE] Reclassified {ip_clean} as {role.upper()} entity",
        })
    return jsonify({"success": True, "ip": ip_clean, "role": role})


@app.route("/api/upstream")
def api_upstream():
    """Returns strictly the single active router/device currently providing internet to this laptop."""
    with STATE_LOCK:
        raw_list = STATE.get("upstream_devices", global_device_tracker.get_upstream_devices())
        active_only = [
            d for d in raw_list 
            if d.get("is_active_uplink") or (d.get("status") and "active" in d.get("status").lower())
        ]
        if active_only:
            return jsonify(active_only[:1])
        return jsonify(raw_list[:1] if raw_list else [])


@app.route("/api/history")
def api_history():
    with STATE_LOCK:
        return jsonify(list(STATE["history"]))


@app.route("/api/graph")
def api_graph():
    with STATE_LOCK:
        return jsonify(STATE["graph"])


@app.route("/api/allocation")
def api_allocation():
    with STATE_LOCK:
        alloc_meta = STATE.get("allocation_meta", {})
        colors = {k: meta["color"] for k, meta in TRAFFIC_CATEGORIES.items()}

        cat_sums = {k: 0.0 for k in TRAFFIC_CATEGORIES}
        for d in STATE["devices"].values():
            cat = d.get("category", "Normal")
            if cat in cat_sums:
                cat_sums[cat] = round(cat_sums[cat] + d.get("allocated_mbps", 0.0), 2)

        return jsonify({
            "allocation": cat_sums,
            "device_allocations": STATE.get("allocation", {}),
            "colors": colors,
            "congestion": STATE.get("congestion", "low"),
            "total_capacity": CONFIG.get("capacity_mbps", 50.0),
            "action_desc": alloc_meta.get("action_desc", "Weighted Fair-Share"),
            "jains_index": alloc_meta.get("jains_index", 1.0),
            "reward": alloc_meta.get("reward", 1.0),
        })


@app.route("/api/log")
def api_log():
    with STATE_LOCK:
        return jsonify(list(STATE["decision_log"]))


@app.route("/api/ml/model")
def api_ml_model():
    """Returns Machine Learning Random Forest classifier metadata, features, and importances."""
    return jsonify(global_classifier.ml_classifier.get_summary())


@app.route("/api/traffic")
def api_traffic():
    return jsonify(global_monitor.cumulative_stats)


@app.route("/api/prediction")
def api_prediction():
    """Returns observed series vs short-term future forecasts and MAE evaluation."""
    with STATE_LOCK:
        mem_hist = list(STATE["history"])
    pred_res = global_predictor.forecast(memory_history=mem_hist, horizon=6)
    return jsonify(pred_res)


@app.route("/api/enforcement", methods=["GET", "POST"])
def api_enforcement():
    """Controls QoS enforcement mode and actions."""
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        action = data.get("action")

        if action == "set_mode":
            mode = data.get("mode", "simulation")
            admin_auth = bool(data.get("admin_authorized", False))
            res = global_qos_controller.set_mode(mode, admin_authorized=admin_auth)
            return jsonify(res)

        elif action == "reset_all":
            res = global_qos_controller.reset_all_limits()
            return jsonify(res)

        elif action == "apply_limit":
            ip = data.get("ip")
            rate = data.get("rate_mbps")
            res = global_qos_controller.enforce_bandwidth_limit(ip, rate)
            return jsonify(res)

        return jsonify({"success": False, "error": f"Unknown action '{action}'"}), 400

    return jsonify(global_qos_controller.get_status())


@app.route("/api/evaluation")
def api_evaluation():
    """Runs and returns live comparative evaluation benchmark."""
    res = run_comparative_experiment()
    return jsonify(res)


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        if "capacity_mbps" in data:
            valid, val = validate_capacity(data["capacity_mbps"])
            if valid:
                CONFIG["capacity_mbps"] = val
                global_allocation_engine.capacity_mbps = val
        if "interface" in data and data["interface"]:
            CONFIG["interface"] = data["interface"]
        if "demo_mode" in data:
            CONFIG["demo_mode"] = bool(data["demo_mode"])

    available = [iface["name"] for iface in global_monitor.get_available_interfaces()]
    return jsonify({**CONFIG, "available_interfaces": available})


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------
def start_application():
    global_monitor.start_capture_thread()
    ctrl_thread = threading.Thread(target=background_control_loop, daemon=True, name="NetPilotControlLoop")
    ctrl_thread.start()


start_application()

if __name__ == "__main__":
    print("=" * 70)
    print("NetPilot AI — Intelligent Bandwidth Management Console")
    print(f"Platform: {platform.system()} | Scapy: {'AVAILABLE' if SCAPY_AVAILABLE else 'UNAVAILABLE'}")
    print(f"Traffic Persistence: {TRAFFIC_CSV}")
    print(f"Enforcement Initial Mode: {global_qos_controller.mode.upper()}")
    print("=" * 70)
    app.run(host="0.0.0.0", port=5000, debug=False)
