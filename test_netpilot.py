"""
NetPilot AI — Automated Test Suite
==================================
Covers:
1. Bandwidth allocation capacity constraints & non-negativity
2. Fair-share and priority-based allocation logic
3. Traffic classification & confidence scoring
4. Device discovery, input validation & sanitization
5. Traffic prediction (SMA, Holt-Winters trend, MAE)
6. Knowledge graph entity & relationship consistency
7. QoS enforcement layer (dry-run, safety validation, rollback)
8. Flask API endpoints & error handling
9. Traffic accounting: byte-to-Mbps, upload/download direction, cumulative totals
10. Subnet-aware device discovery: gateway & local host exclusion, single client isolation
"""

import unittest
import json
import time
from unittest.mock import patch, MagicMock

from config import validate_capacity, validate_ip, validate_rate_limit, CONFIG, get_system_gateways_and_local_ips
from traffic_classifier import TrafficClassifier
from device_discovery import DeviceTracker, parse_arp_sections
from network_monitor import NetworkMonitor
from allocation_engine import AllocationEngine, calculate_jains_fairness_index
from qos_controller import QoSController, SimulationAdapter
from traffic_predictor import TrafficPredictor
from knowledge_graph import NetworkKnowledgeGraph
from app import app, format_bytes


class TestAllocationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = AllocationEngine(capacity_mbps=50.0)

    def test_capacity_constraint_under_heavy_load(self):
        """Allocations must never exceed total configured capacity."""
        devices = {
            "192.168.137.11": {"ip": "192.168.137.11", "priority": "High", "online": True, "used_mbps": 40.0},
            "192.168.137.12": {"ip": "192.168.137.12", "priority": "Normal", "online": True, "used_mbps": 30.0},
            "192.168.137.13": {"ip": "192.168.137.13", "priority": "Low", "online": True, "used_mbps": 20.0},
        }
        res = self.engine.compute_allocation(devices, total_used_mbps=48.0)
        total_allocated = sum(res["allocations"].values())
        self.assertLessEqual(total_allocated, 50.0 + 1e-6)
        self.assertGreater(total_allocated, 0.0)

    def test_priority_awareness(self):
        """High priority devices must receive strictly more bandwidth than Normal and Low under contention."""
        devices = {
            "192.168.137.11": {"ip": "192.168.137.11", "priority": "High", "online": True, "used_mbps": 20.0},
            "192.168.137.12": {"ip": "192.168.137.12", "priority": "Normal", "online": True, "used_mbps": 20.0},
            "192.168.137.13": {"ip": "192.168.137.13", "priority": "Low", "online": True, "used_mbps": 20.0},
        }
        res = self.engine.compute_allocation(devices, total_used_mbps=45.0)
        alloc = res["allocations"]
        self.assertGreater(alloc["192.168.137.11"], alloc["192.168.137.12"])
        self.assertGreater(alloc["192.168.137.12"], alloc["192.168.137.13"])

    def test_single_client_allocation(self):
        """When only one client is active, it gets valid allocation within capacity without error."""
        devices = {
            "192.168.137.75": {"ip": "192.168.137.75", "priority": "Normal", "online": True, "used_mbps": 12.0},
        }
        res = self.engine.compute_allocation(devices, total_used_mbps=12.0)
        self.assertIn("192.168.137.75", res["allocations"])
        self.assertLessEqual(res["allocations"]["192.168.137.75"], 50.0)
        self.assertGreater(res["allocations"]["192.168.137.75"], 0.0)

    def test_inactive_device_zero_allocation(self):
        """Offline devices must receive 0 Mbps so bandwidth is not wasted."""
        devices = {
            "192.168.137.11": {"ip": "192.168.137.11", "priority": "High", "online": True, "used_mbps": 5.0},
            "192.168.137.12": {"ip": "192.168.137.12", "priority": "High", "online": False, "used_mbps": 0.0},
        }
        res = self.engine.compute_allocation(devices, total_used_mbps=5.0)
        self.assertEqual(res["allocations"]["192.168.137.12"], 0.0)
        self.assertGreater(res["allocations"]["192.168.137.11"], 0.0)

    def test_no_negative_allocations(self):
        """Allocations must strictly be >= 0.0."""
        devices = {
            "192.168.137.11": {"ip": "192.168.137.11", "priority": "Low", "online": True, "used_mbps": 0.0},
        }
        res = self.engine.compute_allocation(devices, total_used_mbps=0.0)
        for ip, val in res["allocations"].items():
            self.assertGreaterEqual(val, 0.0)

    def test_jains_fairness_index(self):
        """Jain's index should be 1.0 for equal allocations and < 1.0 for skewed."""
        equal_alloc = [10.0, 10.0, 10.0, 10.0]
        self.assertAlmostEqual(calculate_jains_fairness_index(equal_alloc), 1.0, places=2)
        skewed_alloc = [40.0, 5.0, 3.0, 2.0]
        self.assertLess(calculate_jains_fairness_index(skewed_alloc), 0.8)


class TestTrafficAccounting(unittest.TestCase):
    def setUp(self):
        self.monitor = NetworkMonitor()

    def test_byte_to_mbps_conversion(self):
        """Verify bits per second / 1,000,000 formula for throughput."""
        # 1,250,000 bytes over 1.0 second = 10,000,000 bits = 10.0 Mbps
        delta_bytes = 1_250_000
        dt = 1.0
        mbps = round((delta_bytes * 8) / (dt * 1_000_000), 2)
        self.assertEqual(mbps, 10.0)

    def test_direction_accounting_download_vs_upload(self):
        """Verify destination is attributed as Rx (download) and source as Tx (upload)."""
        client_ip = "192.168.137.75"
        server_ip = "142.250.77.99"

        try:
            from scapy.all import IP, TCP
            rx_pkt = IP(src=server_ip, dst=client_ip) / TCP(sport=443, dport=54321) / (b"X" * 1400)
            tx_pkt = IP(src=client_ip, dst=server_ip) / TCP(sport=54321, dport=443) / (b"X" * 700)
        except Exception:
            self.skipTest("Scapy not available for packet test")

        with patch("network_monitor.get_system_gateways_and_local_ips", return_value=(set(), {"192.168.137.1"})):
            self.monitor._packet_callback(rx_pkt)
            self.monitor._packet_callback(tx_pkt)

        self.assertIn(client_ip, self.monitor.cumulative_stats)
        self.assertGreater(self.monitor.cumulative_stats[client_ip]["total_rx_bytes"], 1000)
        self.assertEqual(self.monitor.cumulative_stats[client_ip]["total_rx_packets"], 1)
        self.assertGreater(self.monitor.cumulative_stats[client_ip]["total_tx_bytes"], 500)
        self.assertEqual(self.monitor.cumulative_stats[client_ip]["total_tx_packets"], 1)

    def test_cumulative_counters_do_not_reset_on_poll(self):
        """Cumulative bytes must persist across polling intervals."""
        client_ip = "192.168.137.75"
        self.monitor.cumulative_stats[client_ip] = {
            "total_rx_bytes": 5000,
            "total_tx_bytes": 2000,
            "total_rx_packets": 10,
            "total_tx_packets": 5,
            "recent_ports": [],
            "last_seen": time.time(),
        }

        # First snapshot
        snap1 = self.monitor.get_device_traffic_snapshot([client_ip])
        self.assertEqual(snap1[client_ip]["total_rx_bytes"], 5000)
        self.assertEqual(snap1[client_ip]["total_packets"], 15)

        # Second snapshot with additional bytes
        self.monitor.cumulative_stats[client_ip]["total_rx_bytes"] += 2500
        self.monitor.cumulative_stats[client_ip]["total_rx_packets"] += 2
        snap2 = self.monitor.get_device_traffic_snapshot([client_ip])

        self.assertEqual(snap2[client_ip]["total_rx_bytes"], 7500)
        self.assertEqual(snap2[client_ip]["total_packets"], 17)

    def test_format_bytes_helper(self):
        self.assertEqual(format_bytes(500), "500.0 B")
        self.assertEqual(format_bytes(2048), "2.0 KB")
        self.assertEqual(format_bytes(1048576 * 5), "5.0 MB")


class TestSubnetAwareDeviceDiscovery(unittest.TestCase):
    def setUp(self):
        self.tracker = DeviceTracker()

    @patch("device_discovery.get_system_gateways_and_local_ips")
    @patch("device_discovery.parse_arp_sections")
    @patch("device_discovery.ping_host", return_value=(True, 15.0))
    def test_gateway_and_host_exclusion(self, mock_ping, mock_arp, mock_sys):
        """The upstream gateway (172.20.10.1) and host PC (192.168.137.1) must NEVER be included as clients."""
        mock_sys.return_value = ({"172.20.10.1"}, {"192.168.137.1", "172.20.10.12"})
        mock_arp.return_value = {
            "192.168.137.1": {
                "192.168.137.75": "a2:07:55:26:ed:31",
            },
            "172.20.10.12": {
                "172.20.10.1": "76:42:18:44:7a:64",
            }
        }

        devices = self.tracker.scan_network()

        # The only client should be 192.168.137.75
        self.assertIn("192.168.137.75", devices)
        self.assertNotIn("172.20.10.1", devices)
        self.assertNotIn("192.168.137.1", devices)
        self.assertNotIn("172.20.10.12", devices)
        self.assertEqual(len(devices), 1)

        # Check diagnostic registry has reasons
        diag = self.tracker.get_diagnostics()
        self.assertEqual(diag["all_entities"]["172.20.10.1"]["classification"], "gateway")
        self.assertEqual(diag["all_entities"]["192.168.137.75"]["classification"], "client")

    @patch("device_discovery.get_system_gateways_and_local_ips")
    @patch("device_discovery.parse_arp_sections")
    def test_empty_candidate_device_list(self, mock_arp, mock_sys):
        """When no clients are connected, returns clean empty dict without errors."""
        mock_sys.return_value = ({"172.20.10.1"}, {"172.20.10.12"})
        mock_arp.return_value = {
            "172.20.10.12": {"172.20.10.1": "76:42:18:44:7a:64"}
        }
        devices = self.tracker.scan_network()
        self.assertEqual(len(devices), 0)


class TestTrafficClassifier(unittest.TestCase):
    def setUp(self):
        self.classifier = TrafficClassifier()

    def test_voip_port_classification(self):
        res = self.classifier.classify_by_port(3478)
        self.assertEqual(res["category"], "High")
        self.assertEqual(res["service"], "STUN/TURN")
        self.assertGreaterEqual(res["confidence"], 0.90)

    def test_https_port_classification(self):
        res = self.classifier.classify_by_port(443)
        self.assertEqual(res["category"], "Normal")
        self.assertEqual(res["service"], "HTTPS/TLS")

    def test_bittorrent_classification(self):
        res = self.classifier.classify_by_port(6881)
        self.assertEqual(res["category"], "Low")

    def test_ephemeral_port_unknown(self):
        res = self.classifier.classify_by_port(52140)
        self.assertEqual(res["category"], "Unknown")
        self.assertLessEqual(res["confidence"], 0.50)


class TestInputValidation(unittest.TestCase):
    def test_valid_ipv4(self):
        valid, clean = validate_ip("192.168.137.14")
        self.assertTrue(valid)
        self.assertEqual(clean, "192.168.137.14")

    def test_invalid_ipv4_rejection(self):
        valid, _ = validate_ip("999.999.1.1")
        self.assertFalse(valid)
        valid, _ = validate_ip("192.168.1.1; rm -rf /")
        self.assertFalse(valid)

    def test_rate_limit_validation(self):
        valid, clean = validate_rate_limit("15.5")
        self.assertTrue(valid)
        self.assertEqual(clean, 15.5)

        valid, _ = validate_rate_limit("-5.0")
        self.assertFalse(valid)
        valid, _ = validate_rate_limit("0.0")
        self.assertFalse(valid)

    def test_capacity_validation(self):
        valid, clean = validate_capacity("100")
        self.assertTrue(valid)
        self.assertEqual(clean, 100.0)

        valid, _ = validate_capacity("-10")
        self.assertFalse(valid)


class TestTrafficPredictor(unittest.TestCase):
    def setUp(self):
        self.predictor = TrafficPredictor()

    def test_insufficient_data_handling(self):
        res = self.predictor.forecast(memory_history=[{"down": 1.0}], horizon=5)
        self.assertEqual(res["status"], "insufficient_data")
        self.assertEqual(len(res["forecast"]), 0)

    def test_forecasting_with_sufficient_data(self):
        series = [{"down": float(i * 1.5)} for i in range(15)]
        res = self.predictor.forecast(memory_history=series, horizon=6)
        self.assertEqual(res["status"], "ready")
        self.assertEqual(len(res["forecast"]), 6)
        self.assertIn("mae", res)
        self.assertGreaterEqual(res["mae"], 0.0)

    def test_mae_calculation(self):
        actual = [10.0, 20.0, 30.0]
        pred = [12.0, 18.0, 33.0]
        mae = self.predictor.calculate_mae(actual, pred)
        self.assertAlmostEqual(mae, 2.333, places=2)


class TestKnowledgeGraph(unittest.TestCase):
    def setUp(self):
        self.kg = NetworkKnowledgeGraph()

    def test_graph_structure(self):
        devices = {
            "192.168.137.11": {"ip": "192.168.137.11", "hostname": "Test-Phone", "online": True, "priority": "High", "status": "confirmed_active"},
        }
        alloc_data = {
            "allocations": {"192.168.137.11": 25.0},
            "explanations": {"192.168.137.11": "High priority allocation"},
            "action_desc": "Test Action",
            "jains_index": 1.0,
        }
        graph = self.kg.build_graph("Wi-Fi", devices, alloc_data, "low", 50.0)

        node_ids = [n["id"] for n in graph["nodes"]]
        self.assertIn("iface:Wi-Fi", node_ids)
        self.assertIn("core:NetPilot", node_ids)
        self.assertIn("class:High", node_ids)
        self.assertIn("dev:192.168.137.11", node_ids)

        dev_node = next(n for n in graph["nodes"] if n["id"] == "dev:192.168.137.11")
        self.assertIn("properties", dev_node)
        self.assertEqual(dev_node["properties"]["IP Address"], "192.168.137.11")
        self.assertGreater(len(graph["edges"]), 0)


class TestQoSController(unittest.TestCase):
    def setUp(self):
        self.qos = QoSController()

    def test_dry_run_simulation(self):
        self.qos.set_mode("simulation")
        res = self.qos.enforce_bandwidth_limit("192.168.137.15", 12.0)
        self.assertTrue(res["success"])
        self.assertEqual(res["mode"], "simulation")
        self.assertIn("192.168.137.15", self.qos.sim_adapter.active_limits)

    def test_privileged_mode_requires_admin_authorization(self):
        res = self.qos.set_mode("windows_qos", admin_authorized=False)
        self.assertFalse(res["success"])

    def test_command_injection_prevention(self):
        res = self.qos.enforce_bandwidth_limit("192.168.1.1 & calc.exe", 10.0)
        self.assertFalse(res["success"])

    def test_reset_all_limits(self):
        self.qos.set_mode("simulation")
        self.qos.enforce_bandwidth_limit("192.168.137.15", 10.0)
        reset_res = self.qos.reset_all_limits()
        self.assertTrue(reset_res["success"])
        self.assertEqual(len(self.qos.sim_adapter.active_limits), 0)


class TestFlaskAPI(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_index_route(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"NetPilot", res.data)

    def test_status_endpoint(self):
        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("capacity_mbps", data)
        self.assertIn("congestion", data)
        self.assertIn("qos_mode", data)
        self.assertIn("packets_captured", data)

    def test_devices_endpoint(self):
        res = self.client.get("/api/devices")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.get_json(), list)

    def test_diagnostics_endpoint(self):
        res = self.client.get("/api/diagnostics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("detected_gateways", data)
        self.assertIn("detected_local_ips", data)
        self.assertIn("all_entities", data)

    def test_prediction_endpoint(self):
        res = self.client.get("/api/prediction")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("status", data)

    def test_device_priority_endpoint(self):
        res = self.client.post(
            "/api/device/priority",
            data=json.dumps({"ip": "192.168.137.12", "priority": "High"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()["success"])

        res_inv = self.client.post(
            "/api/device/priority",
            data=json.dumps({"ip": "192.168.137.12", "priority": "SuperHigh"}),
            content_type="application/json"
        )
        self.assertEqual(res_inv.status_code, 400)

    def test_evaluation_benchmark_endpoint(self):
        res = self.client.get("/api/evaluation")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("policies", data)
        self.assertIn("Static Allocation", data["policies"])
        self.assertIn("Equal Fair-Share", data["policies"])
        self.assertIn("Priority-Based (SPQ)", data["policies"])
        self.assertIn("NetPilot AI (Priority-Aware WFQ + RL)", data["policies"])

        # Check all 5 evaluation metrics for each policy
        for p_name, metrics in data["policies"].items():
            self.assertIn("latency_ms", metrics, f"Missing latency_ms in {p_name}")
            self.assertIn("throughput_mbps", metrics, f"Missing throughput_mbps in {p_name}")
            self.assertIn("jains_fairness", metrics, f"Missing jains_fairness in {p_name}")
            self.assertIn("voip_satisfaction_pct", metrics, f"Missing voip_satisfaction_pct in {p_name}")
            self.assertIn("unmet_demand_pct", metrics, f"Missing unmet_demand_pct in {p_name}")


    def test_block_and_upstream_endpoints(self):
        """Test REST API endpoints for blocking and upstream management."""
        # Test block endpoint
        res = self.client.post(
            "/api/device/block",
            data=json.dumps({"ip": "192.168.137.88", "blocked": True}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()["blocked"])

        # Test unblock endpoint
        res_unblock = self.client.post(
            "/api/device/block",
            data=json.dumps({"ip": "192.168.137.88", "blocked": False}),
            content_type="application/json"
        )
        self.assertEqual(res_unblock.status_code, 200)
        self.assertFalse(res_unblock.get_json()["blocked"])

        # Test set role endpoint
        res_role = self.client.post(
            "/api/device/role",
            data=json.dumps({"ip": "192.168.137.88", "role": "upstream"}),
            content_type="application/json"
        )
        self.assertEqual(res_role.status_code, 200)
        self.assertEqual(res_role.get_json()["role"], "upstream")

        # Test GET /api/upstream
        res_up = self.client.get("/api/upstream")
        self.assertEqual(res_up.status_code, 200)
        data = res_up.get_json()
        self.assertIsInstance(data, list)
        self.assertTrue(any(u["ip"] == "192.168.137.88" for u in data))


class TestAdvancedModules(unittest.TestCase):
    def test_ml_traffic_classifier_model(self):
        """Test Scikit-Learn Random Forest traffic classifier."""
        from traffic_classifier import global_classifier
        ml = global_classifier.ml_classifier
        summary = ml.get_summary()
        self.assertTrue(summary["is_trained"])
        self.assertEqual(summary["model_type"], "RandomForestClassifier (Scikit-Learn)")
        self.assertIn("is_udp", summary["feature_importances"])

        # Test VoIP flow prediction (UDP, port 3478, small 180B packets) -> High
        voip_pred = ml.predict_flow(port=3478, is_udp=True, packet_size=180, rate_mbps=1.5)
        self.assertEqual(voip_pred["category"], "High")
        self.assertGreaterEqual(voip_pred["confidence"], 0.60)

        # Test Bulk flow prediction (TCP, port 6881, large 1490B packets) -> Low
        bulk_pred = ml.predict_flow(port=6881, is_udp=False, packet_size=1490, rate_mbps=20.0)
        self.assertEqual(bulk_pred["category"], "Low")

    def test_tls_sni_and_app_identification(self):
        """Test extraction of TLS SNI hostname and application classification."""
        from traffic_classifier import extract_tls_sni, identify_app_from_domain, global_classifier

        # 1. Test identify_app_from_domain catalog
        yt = identify_app_from_domain("rr1---sn-cvh76nes.googlevideo.com")
        self.assertEqual(yt["app"], "YouTube")
        self.assertIn("Video", yt["category"])

        insta = identify_app_from_domain("scontent.cdninstagram.com")
        self.assertEqual(insta["app"], "Instagram")

        wa = identify_app_from_domain("media-bom1-1.cdn.whatsapp.net")
        self.assertEqual(wa["app"], "WhatsApp")
        self.assertEqual(wa["priority"], "High")

        # 2. Test TLS SNI binary parser on synthetic Client Hello
        sni_name = b"discord.com"
        ext_data = b"\x00" + len(sni_name).to_bytes(2, "big") + sni_name
        sni_ext = b"\x00\x00" + (len(ext_data) + 2).to_bytes(2, "big") + len(ext_data).to_bytes(2, "big") + ext_data
        exts_block = len(sni_ext).to_bytes(2, "big") + sni_ext
        hs_body = b"\x03\x03" + (b"\xaa" * 32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + exts_block
        hs_hdr = b"\x01" + len(hs_body).to_bytes(3, "big") + hs_body
        tls_record = b"\x16\x03\x01" + len(hs_hdr).to_bytes(2, "big") + hs_hdr

        extracted = extract_tls_sni(tls_record)
        self.assertEqual(extracted, "discord.com")

        # 3. Test recording domain on device and classification
        test_ip = "192.168.137.77"
        global_classifier.record_domain(test_ip, "scontent.cdninstagram.com")
        c_res = global_classifier.classify_device_traffic(test_ip)
        self.assertIn("Instagram", c_res["service"])
        self.assertEqual(c_res["recent_domain"], "scontent.cdninstagram.com")

    def test_networkx_knowledge_graph(self):
        """Test NetworkX graph generation and centrality calculation."""
        from knowledge_graph import global_knowledge_graph
        devices = {
            "192.168.137.11": {"online": True, "priority": "High", "hostname": "Zoom-Device"},
            "192.168.137.12": {"online": True, "priority": "Low", "hostname": "Bulk-Downloader"},
        }
        alloc_data = {
            "allocations": {"192.168.137.11": 15.0, "192.168.137.12": 5.0},
            "explanations": {},
        }
        res = global_knowledge_graph.build_graph("Wi-Fi", devices, alloc_data, "low", 50.0)
        self.assertIn("nx_analytics", res)
        self.assertIn("total_nodes", res["nx_analytics"])
        self.assertGreater(res["nx_analytics"]["total_nodes"], 5)
        self.assertIn("degree_centrality", res["nx_analytics"])

        # Verify NetworkX centrality in node properties
        core_node = next(n for n in res["nodes"] if n["id"] == "core:NetPilot")
        self.assertIn("NetworkX Centrality", core_node["properties"])

    def test_block_and_upstream_device_functionality(self):
        """Test blocking Internet and upstream device role separation."""
        from device_discovery import global_device_tracker
        from allocation_engine import global_allocation_engine

        test_ip = "192.168.137.99"
        # 1. Block device
        global_device_tracker.block_device(test_ip, blocked=True)
        self.assertTrue(global_device_tracker.is_device_blocked(test_ip))

        # Check allocation engine enforces 0.0 Mbps for blocked device
        devices = {
            test_ip: {"ip": test_ip, "online": True, "priority": "High", "used_mbps": 10.0, "blocked": True},
            "192.168.137.100": {"ip": "192.168.137.100", "online": True, "priority": "Normal", "used_mbps": 5.0, "blocked": False}
        }
        res = global_allocation_engine.compute_allocation(devices, total_used_mbps=15.0)
        self.assertEqual(res["allocations"][test_ip], 0.0)
        self.assertIn("blocked", res["explanations"][test_ip].lower())
        self.assertGreater(res["allocations"]["192.168.137.100"], 0.0)

        # 2. Unblock device
        global_device_tracker.block_device(test_ip, blocked=False)
        self.assertFalse(global_device_tracker.is_device_blocked(test_ip))

        # 3. Upstream role assignment
        global_device_tracker.set_device_role(test_ip, "upstream")
        upstream = global_device_tracker.get_upstream_devices()
        self.assertTrue(any(u["ip"] == test_ip for u in upstream))

        # Reset role back to client
        global_device_tracker.set_device_role(test_ip, "client")
        upstream_after = global_device_tracker.get_upstream_devices()
        self.assertFalse(any(u["ip"] == test_ip for u in upstream_after))

    def test_holt_winters_and_peak_hour_analysis(self):
        """Test Holt-Winters Triple Smoothing and Diurnal Peak Hour analysis."""
        from traffic_predictor import global_predictor
        # Test Holt-Winters on synthesized series
        series = [1.2, 1.5, 2.0, 1.8, 1.4, 1.6, 2.2, 2.0, 1.5, 1.7, 2.4, 2.1]
        fitted, forecast = global_predictor._holt_winters_triple_smoothing(series, horizon=4)
        self.assertEqual(len(forecast), 4)
        self.assertTrue(all(f >= 0.0 for f in forecast))

        # Test peak hour analyzer
        peak_info = global_predictor.analyze_peak_hours()
        self.assertIn("status", peak_info)
        self.assertIn("peak_hours", peak_info)
        self.assertIn("surge_multiplier", peak_info)
        self.assertIn("congestion_risk_pct", peak_info)

    def test_confidence_and_entropy_quantification(self):
        """Test Shannon entropy and calibrated uncertainty decomposition."""
        from traffic_classifier import calculate_shannon_entropy, quantify_flow_uncertainty
        probs = {"High": 0.85, "Normal": 0.10, "Low": 0.05}
        h_raw, h_norm = calculate_shannon_entropy(probs)
        self.assertGreater(h_raw, 0.0)
        self.assertLessEqual(h_norm, 1.0)

        unc = quantify_flow_uncertainty(probs, packet_count=120, has_sni=True)
        self.assertIn("calibrated_confidence", unc)
        self.assertIn("aleatoric_uncertainty", unc)
        self.assertIn("epistemic_uncertainty", unc)
        self.assertGreater(unc["calibrated_confidence"], 0.70)

    def test_demand_forecasting_uncertainty_envelope(self):
        """Test demand forecasting dynamic uncertainty envelope and PICP."""
        from traffic_predictor import global_predictor
        series = [10.0, 11.5, 12.0, 11.8, 12.5, 13.0, 12.8, 13.5]
        fitted, forecast = global_predictor._holt_winters_triple_smoothing(series, horizon=4)
        unc = global_predictor.compute_uncertainty_envelope(series, fitted, forecast)
        self.assertIn("upper_bounds", unc)
        self.assertIn("lower_bounds", unc)
        self.assertEqual(len(unc["upper_bounds"]), 4)
        self.assertEqual(len(unc["lower_bounds"]), 4)
        for ub, lb in zip(unc["upper_bounds"], unc["lower_bounds"]):
            self.assertGreaterEqual(ub, lb)

    def test_tri_modal_safe_rl_governor(self):
        """Test Tri-Modal control mode arbitration (Modes A, B, and C)."""
        from allocation_engine import (
            AllocationEngine,
            CONTROL_MODE_SAFE_RL,
            CONTROL_MODE_BOUNDED_CONSERVATIVE,
            CONTROL_MODE_DETERMINISTIC_FALLBACK,
        )
        engine = AllocationEngine(capacity_mbps=50.0)

        # High confidence & low uncertainty -> Mode A
        mode_a, risk_a, _ = engine.evaluate_control_mode(avg_confidence=0.88, forecast_uncertainty=0.15, avg_latency_ms=20.0)
        self.assertEqual(mode_a, CONTROL_MODE_SAFE_RL)

        # Moderate ambiguity -> Mode B
        mode_b, risk_b, _ = engine.evaluate_control_mode(avg_confidence=0.60, forecast_uncertainty=0.45, avg_latency_ms=30.0)
        self.assertEqual(mode_b, CONTROL_MODE_BOUNDED_CONSERVATIVE)

        # Low confidence or severe forecast drift -> Mode C
        mode_c, risk_c, _ = engine.evaluate_control_mode(avg_confidence=0.35, forecast_uncertainty=0.75, avg_latency_ms=90.0)
        self.assertEqual(mode_c, CONTROL_MODE_DETERMINISTIC_FALLBACK)

    def test_closed_loop_telemetry_feedback(self):
        """Test adaptive threshold calibration via closed-loop edge telemetry."""
        from allocation_engine import AllocationEngine
        engine = AllocationEngine(capacity_mbps=50.0)
        init_hi = engine.confidence_threshold_high
        init_unc = engine.uncertainty_threshold_high

        # Telemetry reports severe bufferbloat and packet drop -> Tightens thresholds
        engine.update_telemetry_feedback(actual_latency_ms=130.0, packet_drop_pct=2.5, queue_depth_pkts=60)
        self.assertGreaterEqual(engine.confidence_threshold_high, init_hi)
        self.assertLessEqual(engine.uncertainty_threshold_high, init_unc)
        self.assertGreater(engine.stats["sla_violations_mitigated"], 0)

    def test_patent_verification_experiments_runner(self):
        """Test full execution of all 5 empirical patent verification experiments."""
        from evaluation import run_all_patent_experiments
        res = run_all_patent_experiments()
        self.assertIn("experiment_1_classification", res)
        self.assertIn("experiment_2_forecasting", res)
        self.assertIn("experiment_3_allocation", res)
        self.assertIn("experiment_4_safety_ablation", res)
        self.assertIn("experiment_5_edge_overhead", res)


if __name__ == "__main__":
    unittest.main(verbosity=2)
