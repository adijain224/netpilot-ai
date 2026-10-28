"""
NetPilot AI — Network Monitoring Module
=======================================
Handles physical interface discovery, aggregate link throughput via OS counters
(psutil), per-client packet capture via Scapy/Npcap, and cumulative traffic accounting.

Traffic Accounting Direction Convention:
- Client Download (Rx): Packets where destination IP matches the client (dst == client_ip).
- Client Upload (Tx): Packets where source IP matches the client (src == client_ip).
Throughput is calculated via differential byte delta over elapsed polling duration dt.
"""

import os
import csv
import socket
import threading
import time
import ipaddress
from typing import Dict, Any, List, Optional, Tuple, Set

import psutil
from config import CONFIG, TRAFFIC_CSV, DATA_DIR, get_system_gateways_and_local_ips
from traffic_classifier import global_classifier

# Optional packet sniffing with Scapy/Npcap
try:
    from scapy.all import sniff, IP, TCP, UDP
    from scapy.arch.windows import get_windows_if_list
    SCAPY_AVAILABLE = True
except Exception:
    sniff = IP = TCP = UDP = None
    get_windows_if_list = None
    SCAPY_AVAILABLE = False

CSV_FIELDS = [
    "Device", "Download Mbps", "Upload Mbps", "Packets", "Total Rx Bytes", "Total Tx Bytes", "Latency", "Timestamp"
]


class NetworkMonitor:
    """Manages real-time interface monitoring, packet sniffing, and traffic accounting."""

    def __init__(self):
        self.packet_stats_lock = threading.Lock()
        
        # Cumulative per-client accounting: ip -> {total_rx_bytes, total_tx_bytes, total_rx_packets, total_tx_packets, last_seen, recent_ports}
        self.cumulative_stats: Dict[str, Dict[str, Any]] = {}
        
        # Snapshot state for delta throughput calculation
        self.prev_rates: Dict[str, Dict[str, Any]] = {}  # ip -> {prev_rx, prev_tx, prev_t, rx_mbps, tx_mbps}
        
        self.capture_status = {
            "status": "idle",
            "interface": None,
            "error": None,
            "packets_captured": 0,
            "last_packet_time": None,
        }
        
        self.counters_prev = None
        self.last_poll_time = time.time()
        self._capture_thread = None
        self._stop_capture = threading.Event()
        self._ensure_csv()

    def _ensure_csv(self):
        """Ensure the traffic history directory and CSV file exist with correct headers."""
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(TRAFFIC_CSV) or os.path.getsize(TRAFFIC_CSV) == 0:
            with open(TRAFFIC_CSV, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                writer.writeheader()

    def get_available_interfaces(self) -> List[Dict[str, Any]]:
        """Return a structured list of all network interfaces on the system."""
        results = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, addr_list in addrs.items():
            ipv4 = None
            mac = None
            for a in addr_list:
                if a.family == socket.AF_INET:
                    ipv4 = a.address
                elif getattr(psutil, "AF_LINK", None) and a.family == psutil.AF_LINK:
                    mac = a.address

            stat = stats.get(name)
            is_up = stat.isup if stat else False
            speed_mbps = stat.speed if stat else 0

            # Identify if this is a Mobile Hotspot / Wi-Fi Direct virtual adapter
            is_hotspot = bool(
                (ipv4 and ipv4.startswith("192.168.137."))
                or "wi-fi direct" in name.lower()
                or "local area connection*" in name.lower()
            )

            results.append({
                "name": name,
                "ip": ipv4,
                "mac": mac,
                "is_up": is_up,
                "speed_mbps": speed_mbps,
                "is_hotspot": is_hotspot,
            })
        return results

    def detect_primary_interface(self) -> Optional[str]:
        """
        Auto-detect the active interface.
        If Mobile Hotspot is active, prioritizes hotspot adapter for monitoring client subnet;
        otherwise selects active internet uplink interface (e.g. Wi-Fi).
        """
        interfaces = self.get_available_interfaces()

        # 1. Hotspot interface on 192.168.137.x
        for iface in interfaces:
            if iface["ip"] and iface["ip"].startswith("192.168.137."):
                return iface["name"]

        # 2. Virtual Wi-Fi direct adapter that is UP
        for iface in interfaces:
            if iface["is_up"] and iface.get("is_hotspot"):
                return iface["name"]

        # 3. Active uplink with routable IPv4 (e.g. Wi-Fi)
        for iface in interfaces:
            if iface["is_up"] and iface["ip"] and not iface["ip"].startswith("127.") and not iface["ip"].startswith("169.254."):
                return iface["name"]

        # 4. Any non-loopback with IP
        for iface in interfaces:
            if iface["ip"] and not iface["ip"].startswith("127."):
                return iface["name"]

        return None

    def detect_capture_interface_name(self) -> Optional[str]:
        """
        Detect the best Scapy/Npcap adapter name for packet sniffing.
        Prioritizes the Mobile Hotspot adapter so we observe raw client IP packets (192.168.137.x).
        """
        if CONFIG.get("capture_interface"):
            return CONFIG["capture_interface"]

        if not SCAPY_AVAILABLE or not get_windows_if_list:
            return None

        try:
            win_ifaces = get_windows_if_list()
            
            # Priority 1: Adapter with 192.168.137.x IP
            for item in win_ifaces:
                ips = item.get("ips") or []
                if any(str(ip).startswith("192.168.137.") for ip in ips):
                    return item.get("name") or item.get("description")

            # Priority 2: Microsoft Wi-Fi Direct Virtual Adapter
            for item in win_ifaces:
                desc = (item.get("description") or "").lower()
                name = (item.get("name") or "").lower()
                if "wi-fi direct virtual adapter" in desc or "local area connection* 2" in name or "local area connection* 1" in name:
                    return item.get("name") or item.get("description")

            # Priority 3: Active Wi-Fi physical uplink
            for item in win_ifaces:
                ips = item.get("ips") or []
                if any(str(ip).startswith("172.") or str(ip).startswith("192.168.") for ip in ips):
                    return item.get("name") or item.get("description")

            # Priority 4: First available adapter with an IPv4 address
            for item in win_ifaces:
                ips = item.get("ips") or []
                if any(not str(ip).startswith("127.") and not str(ip).startswith("fe80") for ip in ips):
                    return item.get("name") or item.get("description")

        except Exception as exc:
            self.capture_status["error"] = f"Interface detection error: {exc}"

        return None

    def get_link_throughput(self, interface_name: Optional[str] = None) -> Tuple[float, float]:
        """
        Measure physical interface upload and download throughput (Mbps)
        using OS network I/O counters (psutil).
        """
        iface = interface_name or CONFIG.get("interface") or self.detect_primary_interface()
        if not iface:
            return 0.0, 0.0

        now = time.time()
        dt = max(0.1, now - self.last_poll_time)
        self.last_poll_time = now

        up_mbps = 0.0
        down_mbps = 0.0

        try:
            counters = psutil.net_io_counters(pernic=True).get(iface)
            if counters:
                if self.counters_prev:
                    up_bytes = max(0, counters.bytes_sent - self.counters_prev.bytes_sent)
                    down_bytes = max(0, counters.bytes_recv - self.counters_prev.bytes_recv)
                    up_mbps = round((up_bytes * 8) / (dt * 1_000_000), 2)
                    down_mbps = round((down_bytes * 8) / (dt * 1_000_000), 2)
                self.counters_prev = counters
        except Exception:
            pass

        return up_mbps, down_mbps

    def _packet_callback(self, pkt):
        """
        Scapy packet callback with correct direction attribution:
        - Download (Rx for Client): dst == client_ip (incoming packet to client)
        - Upload (Tx from Client): src == client_ip (outgoing packet from client)
        """
        if not SCAPY_AVAILABLE or IP not in pkt:
            return

        try:
            src = str(pkt[IP].src)
            dst = str(pkt[IP].dst)
            byte_count = len(pkt)
            now = time.time()

            # Ignore loopback and broadcast
            if src.startswith("127.") or dst.startswith("127.") or dst.endswith(".255") or dst.startswith("224."):
                return

            # Check if either end is an administrator-blocked device (Cut-Off enforcement)
            try:
                from device_discovery import global_device_tracker
                if src in global_device_tracker.blocked_ips or dst in global_device_tracker.blocked_ips:
                    if TCP in pkt and SCAPY_AVAILABLE:
                        try:
                            from scapy.all import send
                            rst = IP(src=dst, dst=src) / TCP(
                                sport=pkt[TCP].dport,
                                dport=pkt[TCP].sport,
                                seq=getattr(pkt[TCP], "ack", 0) or 0,
                                flags="R"
                            )
                            send(rst, verbose=0)
                        except Exception:
                            pass
                    return
            except Exception:
                pass

            gateways, local_ips = get_system_gateways_and_local_ips()

            port = None
            if TCP in pkt:
                port = pkt[TCP].dport or pkt[TCP].sport
            elif UDP in pkt:
                port = pkt[UDP].dport or pkt[UDP].sport

            # Determine whether src or dst represents a local client
            with self.packet_stats_lock:
                # 1. Download to Client: dst is in a local private range (e.g. 192.168.137.x) and not the host PC
                if dst.startswith("192.168.137.") and dst not in local_ips:
                    client_ip = dst
                    entry = self.cumulative_stats.setdefault(
                        client_ip,
                        {"total_rx_bytes": 0, "total_tx_bytes": 0, "total_rx_packets": 0, "total_tx_packets": 0, "recent_ports": [], "last_seen": now, "last_tx_time": 0}
                    )
                    entry["total_rx_bytes"] += byte_count
                    entry["total_rx_packets"] += 1
                    entry["last_seen"] = now
                    if port and len(entry["recent_ports"]) < 12 and port not in entry["recent_ports"]:
                        entry["recent_ports"].append(port)
                    global_classifier.record_packet(client_ip, port, byte_count)

                # 2. Upload from Client: src is in a local private range (e.g. 192.168.137.x) and not the host PC
                if src.startswith("192.168.137.") and src not in local_ips:
                    client_ip = src
                    entry = self.cumulative_stats.setdefault(
                        client_ip,
                        {"total_rx_bytes": 0, "total_tx_bytes": 0, "total_rx_packets": 0, "total_tx_packets": 0, "recent_ports": [], "last_seen": now, "last_tx_time": 0}
                    )
                    entry["total_tx_bytes"] += byte_count
                    entry["total_tx_packets"] += 1
                    entry["last_seen"] = now
                    entry["last_tx_time"] = now
                    if port and len(entry["recent_ports"]) < 12 and port not in entry["recent_ports"]:
                        entry["recent_ports"].append(port)
                    global_classifier.record_packet(client_ip, port, byte_count)

                # 3. Fallback for non-hotspot local subnets (if hotspot is not used):
                # If neither src nor dst matched 192.168.137.x, check if dst/src is a local client (non-gateway, non-host)
                if not dst.startswith("192.168.137.") and not src.startswith("192.168.137."):
                    if dst.startswith("172.") and dst not in local_ips and dst not in gateways:
                        client_ip = dst
                        entry = self.cumulative_stats.setdefault(
                            client_ip,
                            {"total_rx_bytes": 0, "total_tx_bytes": 0, "total_rx_packets": 0, "total_tx_packets": 0, "recent_ports": [], "last_seen": now, "last_tx_time": 0}
                        )
                        entry["total_rx_bytes"] += byte_count
                        entry["total_rx_packets"] += 1
                        entry["last_seen"] = now

                    elif src.startswith("172.") and src not in local_ips and src not in gateways:
                        client_ip = src
                        entry = self.cumulative_stats.setdefault(
                            client_ip,
                            {"total_rx_bytes": 0, "total_tx_bytes": 0, "total_rx_packets": 0, "total_tx_packets": 0, "recent_ports": [], "last_seen": now, "last_tx_time": 0}
                        )
                        entry["total_tx_bytes"] += byte_count
                        entry["total_tx_packets"] += 1
                        entry["last_seen"] = now
                        entry["last_tx_time"] = now

                # Deep inspection: Extract active Application from TLS SNI or DNS query
                if client_ip:
                    if TCP in pkt and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
                        try:
                            from scapy.all import Raw
                            from traffic_classifier import extract_tls_sni
                            if Raw in pkt:
                                sni = extract_tls_sni(bytes(pkt[Raw].load))
                                if sni:
                                    global_classifier.record_domain(client_ip, sni)
                        except Exception:
                            pass
                    elif UDP in pkt and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53):
                        try:
                            from scapy.layers.dns import DNS
                            if DNS in pkt and pkt[DNS].qd and getattr(pkt[DNS], "opcode", 0) == 0:
                                qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                                if qname and not qname.endswith(".arpa") and not qname.endswith(".local") and not qname.endswith(".mshome.net"):
                                    global_classifier.record_domain(client_ip, qname)
                        except Exception:
                            pass

                self.capture_status["packets_captured"] += 1
                self.capture_status["last_packet_time"] = now

        except Exception as exc:
            pass

    def start_capture_thread(self):
        """Start background packet capture worker with automatic interface detection and recovery."""
        if not SCAPY_AVAILABLE:
            self.capture_status.update({
                "status": "unavailable",
                "error": "Scapy/Npcap driver not available. Operating in socket throughput mode.",
            })
            return

        if self._capture_thread and self._capture_thread.is_alive():
            return

        self._stop_capture.clear()

        def _capture_worker():
            last_error_time = 0
            while not self._stop_capture.is_set():
                iface = self.detect_capture_interface_name()
                self.capture_status["interface"] = iface

                if not iface:
                    self.capture_status["status"] = "idle"
                    self.capture_status["error"] = "Waiting for suitable capture adapter..."
                    time.sleep(3.0)
                    continue

                try:
                    self.capture_status["status"] = "running"
                    self.capture_status["error"] = None
                    sniff(
                        iface=iface,
                        prn=self._packet_callback,
                        store=False,
                        timeout=2.0,
                    )
                except Exception as exc:
                    now = time.time()
                    if now - last_error_time > 10.0:
                        self.capture_status["status"] = "error"
                        self.capture_status["error"] = str(exc)
                        last_error_time = now
                    time.sleep(2.5)

        self._capture_thread = threading.Thread(target=_capture_worker, daemon=True, name="NetPilotCaptureThread")
        self._capture_thread.start()

    def get_observed_packet_ips(self, max_idle_seconds: float = 10.0) -> Set[str]:
        """Return the set of client IP addresses that have actively transmitted packets (Tx) within the idle window."""
        now = time.time()
        with self.packet_stats_lock:
            return {
                ip for ip, stat in self.cumulative_stats.items()
                if (now - stat.get("last_tx_time", 0)) <= max_idle_seconds
            }

    def get_device_traffic_snapshot(self, client_ips: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """
        Calculate differential throughput (Mbps) and return cumulative stats.
        Preserves cumulative totals across polling cycles.
        """
        now = time.time()
        results: Dict[str, Dict[str, Any]] = {}

        with self.packet_stats_lock:
            all_ips = set(self.cumulative_stats.keys())
            if client_ips:
                all_ips.update(client_ips)

            for ip in all_ips:
                stat = self.cumulative_stats.get(
                    ip,
                    {"total_rx_bytes": 0, "total_tx_bytes": 0, "total_rx_packets": 0, "total_tx_packets": 0, "recent_ports": [], "last_seen": None}
                )

                rx_bytes = stat["total_rx_bytes"]
                tx_bytes = stat["total_tx_bytes"]

                # Calculate throughput delta
                prev_record = self.prev_rates.setdefault(ip, {
                    "prev_rx": rx_bytes,
                    "prev_tx": tx_bytes,
                    "prev_t": now,
                    "rx_mbps": 0.0,
                    "tx_mbps": 0.0,
                })

                dt = max(0.1, now - prev_record["prev_t"])
                delta_rx = max(0, rx_bytes - prev_record["prev_rx"])
                delta_tx = max(0, tx_bytes - prev_record["prev_tx"])

                rx_mbps = round((delta_rx * 8) / (dt * 1_000_000), 3)
                tx_mbps = round((delta_tx * 8) / (dt * 1_000_000), 3)

                prev_record["prev_rx"] = rx_bytes
                prev_record["prev_tx"] = tx_bytes
                prev_record["prev_t"] = now
                prev_record["rx_mbps"] = rx_mbps
                prev_record["tx_mbps"] = tx_mbps

                results[ip] = {
                    "download_mbps": rx_mbps,
                    "upload_mbps": tx_mbps,
                    "total_rx_bytes": rx_bytes,
                    "total_tx_bytes": tx_bytes,
                    "total_packets": stat["total_rx_packets"] + stat["total_tx_packets"],
                    "rx_packets": stat["total_rx_packets"],
                    "tx_packets": stat["total_tx_packets"],
                    "recent_ports": list(stat["recent_ports"]),
                    "last_seen_packet": stat["last_seen"],
                }

        return results

    def append_history(self, rows: List[Dict[str, Any]]):
        """Append traffic measurement rows to CSV."""
        if not rows:
            return
        self._ensure_csv()
        try:
            with open(TRAFFIC_CSV, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                writer.writerows(rows)
        except Exception:
            pass


global_monitor = NetworkMonitor()
