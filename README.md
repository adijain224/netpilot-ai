# NetPilot AI — AI-Driven Bandwidth Optimization & Network Resource Management

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![Flask 3.0](https://img.shields.io/badge/framework-Flask%203.0-green.svg)](https://palletsprojects.com/p/flask/)
[![Tests](https://img.shields.io/badge/tests-38%20passed-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()

> **Final Project Submission Document**  
> **Course / Degree:** Bachelor of Technology / Computer Science & Engineering  
> **Topic:** Intelligent Bandwidth Allocation Using Knowledge Graphs and Reinforcement Learning  

---

## 1. Project Overview & Architecture

**NetPilot AI** is an intelligent network resource management platform designed to monitor live network traffic, discover active client devices, classify traffic flows into explainable priority classes, construct a real-time Network Knowledge Graph, forecast short-term traffic demand, and optimize bandwidth allocation using a priority-aware Weighted Fair Queuing (WFQ) engine augmented by Reinforcement Learning (Q-learning).

### System Architecture Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SENSE & DISCOVER                               │
│  - psutil OS I/O Counters (Physical Link Throughput)                        │
│  - System ARP Table Parsing (`arp -a`)                                      │
│  - ICMP Echo Probing (Active vs Discovered Distinction & Latency)            │
│  - Scapy / Npcap Sniffing (Per-client IP Packet & Transport Accounting)    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          EXPLAINABLE CLASSIFIER                             │
│  - Transport Port & Protocol Signatures (DNS, STUN/WebRTC, HTTP/S, P2P)     │
│  - Priority Tiers: High (VoIP/Gaming), Normal (Web/Cloud), Low (Bulk),      │
│    and Transparent "Unknown" Class                                          │
│  - Observable Evidence Reasoning & Explicit Confidence Scoring [0.0 - 1.0]  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TIME-SERIES DEMAND FORECASTER                            │
│  - Simple Moving Average (SMA) Baseline                                     │
│  - Holt-Winters Linear Exponential Smoothing (Level + Trend Projection)     │
│  - Out-of-Sample Horizon Forecast & Mean Absolute Error (MAE) Metric        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     AI BANDWIDTH ALLOCATION ENGINE                          │
│  - Configurable Uplink/Downlink Capacity & Anti-Starvation Rate Floors      │
│  - User-Configurable Device Priorities (High / Normal / Low)                │
│  - Weighted Max-Min Fair Share & Demand-Aware Surplus Reallocation          │
│  - Contextual Q-Learning Agent (Reward = Jain's Fairness - Latency - Unmet) │
│  - Strict Mathematical Capacity Guarantee: Sum(Allocations) <= Capacity     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                     ┌─────────────────┴─────────────────┐
                     ▼                                   ▼
┌────────────────────────────────────────┐ ┌──────────────────────────────────┐
│        NETWORK KNOWLEDGE GRAPH         │ │      QoS ENFORCEMENT LAYER       │
│  - Data-Backed Vis Network Graph       │ │  - Safe Simulation / Dry-Run     │
│  - Interfaces ↔ Core ↔ Classes ↔ Hosts │ │  - Windows QoS (Local Sockets)   │
│  - Interactive Entity Inspector Panel  │ │  - Linux / OpenWrt `tc` Adapter  │
└────────────────────────────────────────┘ └──────────────────────────────────┘
```

---

## 2. Technical Grounding & Honesty (Real vs. Simulated)

Academic integrity requires clear separation between physical measurements, mathematical models, and deployment constraints:

| Component | Status | Technical Implementation Details |
|---|---|---|
| **Total Link Throughput** | **Real** | Read from physical network adapter hardware counters via `psutil.net_io_counters()`. |
| **Device Discovery** | **Real** | Parsed directly from the operating system ARP cache (`arp -a`). |
| **Confirmed vs Discovered** | **Real** | Distinguishes ARP-cached hosts from confirmed active devices via live ICMP echo (`ping`). |
| **Per-Device Packet Sniffing** | **Real** | Extracted via Npcap / Scapy (`sniff`) tracking source/destination IP bytes when administrator privileges and Npcap are present. |
| **Traffic Classification** | **Real Metadata** | Classifies flows using observable transport ports, protocols, and packet headers. Does **not** claim to decrypt TLS/HTTPS payloads without MITM certificates. |
| **Traffic Demand Forecasting** | **Real Statistical Model** | Holt-Winters exponential smoothing and SMA baselines evaluated with real MAE on collected CSV history. |
| **RL Allocation Policy** | **Real Code & MDP** | Tabular Q-learning agent with documented State, Action, and Multi-Objective Reward function based on Jain's Fairness Index. |
| **Knowledge Graph** | **Real Data Structure** | Live entity-relationship graph rendered dynamically in Vis Network with clickable property inspection. |
| **Windows Bandwidth Enforcement** | **Simulation / Documented Adapter** | **Critical Reality Disclosure:** Windows Mobile Hotspot routes client traffic via Windows Filtering Platform (WFP) and NAT. Windows `New-NetQosPolicy` limits local host sockets, but cannot shape forwarded Wi-Fi Direct frames without a kernel NDIS driver. NetPilot AI provides a safe Dry-Run Simulation mode and a production Linux/OpenWrt `tc` gateway adapter. |

---

## 3. Directory & File Structure

```
c:\netpilot-ai\
├── config.py                 # Centralized configuration, constants, validation helpers
├── network_monitor.py        # Interface detection, psutil counters, Scapy packet sniffer
├── device_discovery.py       # ARP table discovery, ICMP ping health, hostname cache
├── traffic_classifier.py     # Explainable port & protocol classifier with confidence
├── traffic_predictor.py      # Statistical time-series forecasting (SMA, Holt-Winters, MAE)
├── allocation_engine.py      # Weighted Fair Queuing, demand headroom, Q-learning agent
├── qos_controller.py         # Enforcement layer: Simulation, Windows QoS, Linux tc
├── knowledge_graph.py        # Dynamic entity-relationship graph generator
├── evaluation.py             # Reproducible multi-policy benchmarking suite
├── app.py                    # Flask application entry point & API routes
├── test_netpilot.py          # Automated test suite (27 unit & integration tests)
├── requirements.txt          # Python dependencies
├── data/
│   └── traffic_history.csv   # Historical traffic time-series database (3,900+ rows)
├── static/
│   ├── css/
│   │   └── style.css         # Dark theme console UI with responsive layout
│   └── js/
│       └── dashboard.js      # Interactive pollers, Chart.js, Vis Network, node inspector
└── templates/
    └── index.html            # Main operations console interface
```

---

## 4. Installation & Setup on Windows

### Prerequisites

1. **Windows 10 / 11**
2. **Python 3.9 or higher** (Python 3.10 – 3.14 supported)
3. *(Optional for real packet capture)*: **Npcap** ([npcap.com](https://npcap.com/)) installed with *"WinPcap API-compatible Mode"* checked.

### Step 1: Open PowerShell as Administrator

To allow ICMP pinging, ARP table reading, and socket sniffing:
Press `Win + X` → select **Windows PowerShell (Admin)** or **Terminal (Admin)**.

### Step 2: Navigate to the Project Directory

```powershell
cd c:\netpilot-ai
```

### Step 3: Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

---

## 5. Running the Application

### Normal Live Mode (Connected to Wi-Fi / Hotspot)

```powershell
python app.py
```

Open your browser to:
- **Local Console:** `http://localhost:5000`
- **From Connected Devices:** `http://<your-ip>:5000` (e.g., `http://192.168.137.1:5000` or `http://172.20.10.12:5000`)

### Demonstration / Rehearsal Mode (Offline / No External Devices)

If you are rehearsing or presenting without other physical devices connected to your laptop:

```powershell
# In PowerShell:
$env:DEMO_MODE="1"; python app.py

# In Command Prompt:
set DEMO_MODE=1 && python app.py
```

This generates realistic test client profiles (smartphones, workstation, Smart TV) so all charts, the knowledge graph, and the allocation engine are immediately demonstrable.

To return to live mode:
```powershell
$env:DEMO_MODE=""; python app.py
```

---

## 6. Dashboard Features & Controls

1. **Top Bar & Status Chips:**
   - **Interface Status Chip:** Shows the active adapter (e.g., `Wi-Fi`) and monitoring backend (`Sniffing` via Scapy or `Sockets` via psutil).
   - **Enforcement Status Chip:** Displays current QoS mode (`Simulation / Dry-Run`, `Windows NetQos`, or `Linux tc`).
   - **Congestion Chip:** Real-time load level (`LOW`, `MEDIUM`, or `HIGH`).
   - **Benchmark Button:** Opens the experimental performance evaluation modal.
   - **Settings Gear:** Configures link capacity, monitored interface, and enforcement mode.

2. **Key Performance Indicators (KPIs):**
   - **Downlink / Uplink Throughput:** Measured in real time via OS counters.
   - **Avg. Latency:** Live ICMP round-trip time in milliseconds.
   - **Devices Online:** Number of online devices and confirmed active hosts.
   - **Capacity & Fairness:** Configured link capacity and Jain's Fairness Index.

3. **Live Throughput Chart:**
   - Dual-line Chart.js area chart showing historical upload and download bandwidth over rolling polling cycles.

4. **Traffic Demand Forecast Chart:**
   - Compares **Observed Actuals** (solid blue line), **Fitted Baseline SMA** (dashed gray line), and **Short-Term Forecast Horizon** (cyan dashed line).
   - Displays real-time **Mean Absolute Error (MAE)**.

5. **AI Bandwidth Allocation Chart & Legend:**
   - Doughnut visualization of bandwidth distributed across priority classes.
   - Displays the active RL policy mode and Jain's Fairness Index tag.

6. **Network Knowledge Graph & Entity Inspector:**
   - Interactive force-directed topology linking Interfaces ➔ NetPilot Core ➔ Priority Classes ➔ Devices.
   - **Interactive Node Inspector:** Click *any* node in the graph to display its exact attributes (IP, MAC, discovery state, allocated Mbps, and QoS reason).

7. **Connected Devices Management Table:**
   - **Active Status Badge:** Shows `Active (Pinged)` for confirmed devices vs `Discovered (ARP)`.
   - **Interactive Priority Toggle:** Click the priority badge (`High`, `Normal`, `Low`) directly in the table to cycle device priority on the fly.
   - **Traffic Classification:** Displays detected service and confidence tooltip.
   - **AI Allocation & Rationale:** Shows allocated Mbps and transparent decision reason.

8. **Agent & Controller Activity Log:**
   - Running ledger of Q-learning updates, reward scores, and congestion transitions.

---

## 7. Automated Testing

NetPilot AI includes a comprehensive automated test suite in `test_netpilot.py`.

### Run All Automated Tests

```powershell
python -m unittest test_netpilot.py -v
```

### Verified Test Coverage (38 Tests)

- `test_ml_traffic_classifier_model`: Validates Scikit-Learn Random Forest flow classification, feature importances, and class probabilities.
- `test_networkx_knowledge_graph`: Validates NetworkX MultiDiGraph entity relationships, degree centrality, and graph density.
- `test_holt_winters_and_peak_hour_analysis`: Validates Holt-Winters triple exponential smoothing and historical diurnal peak-hour detection.
- `test_capacity_constraint_under_heavy_load`: Verifies $\sum \text{Allocations} \le \text{Capacity}$ under overload.
- `test_priority_awareness`: Confirms High priority receives strictly greater bandwidth than Normal and Low.
- `test_inactive_device_zero_allocation`: Ensures offline hosts receive 0 Mbps, preventing capacity waste.
- `test_no_negative_allocations`: Confirms non-negativity constraint.
- `test_jains_fairness_index`: Validates mathematical fairness calculations.
- `test_voip_port_classification`: Tests STUN/TURN (port 3478) high-priority classification.
- `test_https_port_classification`: Tests HTTPS (port 443) web classification.
- `test_bittorrent_classification`: Tests P2P (port 6881) low-priority classification.
- `test_ephemeral_port_unknown`: Tests ambiguous dynamic port handling.
- `test_valid_ipv4` & `test_invalid_ipv4_rejection`: Tests IP sanitization and command injection prevention.
- `test_rate_limit_validation`: Validates numerical bandwidth constraints.
- `test_forecasting_with_sufficient_data`: Validates Holt-Winters trend forecasting and positive MAE.
- `test_insufficient_data_handling`: Confirms graceful handling of sparse datasets without crashes.
- `test_graph_structure`: Validates Vis Network node/edge topology and inspector properties.
- `test_dry_run_simulation`: Confirms safe simulated token bucket execution.
- `test_privileged_mode_requires_admin_authorization`: Tests security boundary authorization.
- `test_command_injection_prevention`: Verifies command argument sanitization.
- `test_reset_all_limits`: Verifies rollback and policy cleanup routines.
- `test_index_route`, `test_status_endpoint`, `test_devices_endpoint`, `test_prediction_endpoint`, `test_device_priority_endpoint`, `test_evaluation_benchmark_endpoint`: Validates REST API contracts.

---

## 8. Performance Evaluation & Benchmarking

NetPilot AI includes an integrated experimental benchmark comparing four allocation policies under severe link contention (150% load: 75 Mbps competing demand on a 50 Mbps uplink):

### Run Benchmark via Command Line

```powershell
python evaluation.py
```

### Benchmark Results Table

| Allocation Policy | Avg Latency | Throughput | Jain's Fairness Index | VoIP Satisfaction | Unmet Demand (%) | Allocation Overhead |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Static Allocation (Rigid Quota)** | 64.2 ms | 45.0 Mbps | 0.9726 | 100.0% | 40.0% (30.0 Mbps) | 0.011 ms |
| **Equal Fair-Share (Max-Min Equal)** | 58.5 ms | 45.0 Mbps | **1.0000** | 100.0% | 40.0% (30.0 Mbps) | 0.001 ms |
| **Priority-Based (Strict SPQ)** | 42.0 ms | **50.0 Mbps** | 0.9498 | 100.0% | 33.3% (25.0 Mbps) | 0.004 ms |
| **NetPilot AI (Priority-Aware WFQ + RL)** | **21.4 ms** | 44.75 Mbps | 0.9360 | **100.0%** | 40.3% (30.25 Mbps) | 0.053 ms |

### Evaluation Summary
- **Latency Protection:** Under heavy congestion, NetPilot AI provides the lowest queuing latency (**21.4 ms** vs 42–64 ms in baseline policies) via priority queue isolation.
- **Fairness Balance:** NetPilot AI preserves a high Jain's fairness index of **0.9360** while guaranteeing anti-starvation floor progress for bulk downloads.
- **VoIP Guarantee:** Fulfills 100% of real-time interactive traffic demand with headroom.
- **Computational Efficiency:** NetPilot AI computes allocations in **0.053 milliseconds**, easily operating within real-time polling constraints (2.5s intervals).

---

## 9. Manual Windows Testing & Viva Demonstration Checklist

Use this step-by-step checklist during your project demonstration or oral examination:

1. [ ] **Start Console:** Launch PowerShell as Admin, run `python app.py`, and open `http://localhost:5000`.
2. [ ] **Interface Verification:** Confirm top status chip displays active adapter (e.g., `Wi-Fi` or hotspot adapter).
3. [ ] **Device Discovery Check:** Verify discovered devices appear with IP, MAC, and live status.
4. [ ] **Traffic Generation:** Open YouTube or start a file download on a connected phone/browser. Observe throughput spike on the **Link Throughput** chart.
5. [ ] **Inspect Knowledge Graph:** Click any node in the Knowledge Graph. Verify the **Entity Inspector** displays its IP, MAC, status, and allocated bandwidth.
6. [ ] **Dynamic Priority Change:** In the Connected Devices table, click the priority badge for a test device to toggle from `Normal` to `High`. Observe allocation recalculation and decision log entry.
7. [ ] **Traffic Prediction Verification:** Inspect the **Traffic Demand Forecast** chart. Note the observed vs predicted horizon line and MAE metric.
8. [ ] **Run Benchmark Modal:** Click the `Benchmark` button in the top navigation. Verify experimental comparison table renders with Jain's index.
9. [ ] **QoS Safe Reset:** Open Settings modal (`gear` icon), click `Reset All Limits`, and verify that cleanup executes safely without altering system networking.

---

## 10. Common Issues & Troubleshooting

- **Device list is empty:**
  - Give the system 5–10 seconds (one ARP poll cycle).
  - Ensure PowerShell was launched as **Administrator** so ARP table lookups and ICMP pings are not blocked by Windows security policies.
  - If rehearsing without other physical devices on the network, run `$env:DEMO_MODE="1"; python app.py`.
- **Packet capture status shows "unavailable":**
  - psutil socket monitoring will still run seamlessly.
  - To enable deep packet capture, install [Npcap](https://npcap.com/) and run in Administrator mode.
- **Firewall Prompt on First Run:**
  - Click **Allow access** on Private networks so other devices on your LAN/hotspot can reach the dashboard on port 5000.

---

