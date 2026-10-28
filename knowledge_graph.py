"""
NetPilot AI — Network Knowledge Graph Module
============================================
Constructs a data-backed Knowledge Graph representing network entities,
relationships, and policy decisions:
- Network Interfaces (Physical / Virtual)
- Discovered & Active Devices
- Traffic Classes & QoS Priorities
- Allocation Policies & Enforced Decisions

Formats nodes and edges for Vis Network with interactive metadata inspectability.
"""

from typing import Dict, Any, List, Optional

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except Exception:
    nx = None
    NETWORKX_AVAILABLE = False

from config import TRAFFIC_CATEGORIES


class NetworkKnowledgeGraph:
    """
    Builds an interactive entity-relationship Knowledge Graph using NetworkX.
    Maps physical interfaces, controller logic, priority classes, and client devices.
    Exports structured data for Vis Network frontend visualization and property inspection.
    """

    def __init__(self):
        self.nx_graph: Optional[Any] = nx.MultiDiGraph() if NETWORKX_AVAILABLE else None
        self.last_analytics: Dict[str, Any] = {}

    def build_graph(
        self,
        interface_name: str,
        devices: Dict[str, Dict[str, Any]],
        allocation_data: Dict[str, Any],
        congestion: str = "low",
        capacity_mbps: float = 50.0,
        upstream_devices: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate nodes and edges for Vis Network.
        Includes rich properties for node inspection.
        """
        nodes = []
        edges = []

        # 0. Upstream Internet Provider Nodes (e.g. Tethered iPhone, Gateway)
        iface_id = f"iface:{interface_name or 'Default'}"
        if upstream_devices:
            for up in upstream_devices:
                up_id = f"upstream:{up['ip']}"
                up_host = up.get("hostname") or up["ip"]
                nodes.append({
                    "id": up_id,
                    "label": f"Upstream Provider\n{up_host}",
                    "group": "upstream",
                    "shape": "diamond",
                    "size": 18,
                    "color": {"background": "#0284c7", "border": "#38bdf8"},
                    "font": {"color": "#f0f9ff", "face": "Space Grotesk", "size": 11, "bold": True},
                    "properties": {
                        "Type": "Upstream Internet Provider",
                        "Role": up.get("role", "upstream_gateway"),
                        "Hostname": up_host,
                        "IP Address": up["ip"],
                        "MAC Address": up.get("mac", "—"),
                        "Status": up.get("status", "Active Uplink Provider"),
                        "Description": up.get("description", "Supplies Internet bandwidth to host and clients"),
                    },
                    "title": f"Upstream Internet Source: {up_host} ({up['ip']})",
                })
                # Edge from Upstream Provider into Interface
                edges.append({
                    "from": up_id,
                    "to": iface_id,
                    "label": "PROVIDES_INTERNET",
                    "arrows": "to",
                    "color": {"color": "#38bdf8", "opacity": 0.8},
                    "width": 3,
                })

        # 1. Monitored Network Interface Node
        nodes.append({
            "id": iface_id,
            "label": f"Interface\n{interface_name or 'Unknown'}",
            "group": "interface",
            "shape": "box",
            "color": {"background": "#1e293b", "border": "#38bdf8"},
            "font": {"color": "#f8fafc", "face": "Space Grotesk", "size": 11},
            "properties": {
                "Type": "Network Interface",
                "Name": interface_name or "Auto-detected",
                "Monitored": "True",
            },
            "title": f"Interface: {interface_name}",
        })

        # 2. NetPilot Allocation Controller Core Node
        core_id = "core:NetPilot"
        nodes.append({
            "id": core_id,
            "label": f"NetPilot AI\n{congestion.upper()} Load",
            "group": "core",
            "shape": "hexagon",
            "size": 25,
            "color": {
                "background": "#0f766e" if congestion == "low" else ("#b45309" if congestion == "medium" else "#b91c1c"),
                "border": "#2dd4bf",
            },
            "font": {"color": "#ffffff", "face": "Space Grotesk", "size": 12, "bold": True},
            "properties": {
                "Type": "QoS Allocation Engine",
                "Total Capacity": f"{capacity_mbps} Mbps",
                "Congestion State": congestion.upper(),
                "Active Devices": len([d for d in devices.values() if d.get("online")]),
                "Policy Action": allocation_data.get("action_desc", "Weighted Fair-Share"),
                "Jain's Fairness Index": allocation_data.get("jains_index", 1.0),
            },
            "title": f"NetPilot AI Core Controller ({congestion} load)",
        })

        # Link interface to core
        edges.append({
            "from": iface_id,
            "to": core_id,
            "label": "FEEDS",
            "arrows": "to",
            "color": {"color": "#38bdf8", "opacity": 0.6},
            "dashes": False,
        })

        # 3. Traffic Priority Class Nodes
        for cat_name, cat_meta in TRAFFIC_CATEGORIES.items():
            class_id = f"class:{cat_name}"
            nodes.append({
                "id": class_id,
                "label": f"{cat_name}\nClass",
                "group": "category",
                "shape": "dot",
                "size": 16,
                "color": {"background": cat_meta["color"], "border": "#ffffff"},
                "font": {"color": "#f1f5f9", "size": 11},
                "properties": {
                    "Type": "Traffic Priority Class",
                    "Priority Category": cat_name,
                    "Description": cat_meta["label"],
                    "Default Weight": cat_meta["default_weight"],
                },
                "title": f"Priority Class: {cat_name} ({cat_meta['label']})",
            })

            # Link Core to Priority Class
            edges.append({
                "from": core_id,
                "to": class_id,
                "label": f"w={cat_meta['default_weight']}",
                "arrows": "to",
                "color": {"color": cat_meta["color"], "opacity": 0.5},
            })

        # 4. Connected Device Nodes & Allocation Edges
        alloc_map = allocation_data.get("allocations", {})
        expl_map = allocation_data.get("explanations", {})

        for ip, d in devices.items():
            dev_id = f"dev:{ip}"
            is_online = d.get("online", False)
            prio = d.get("priority", "Normal")
            hostname = d.get("hostname") or ip
            allocated = alloc_map.get(ip, 0.0)
            status_text = d.get("status", "discovered_only")

            # Border color indicates active vs discovered
            border_color = "#34d399" if status_text == "confirmed_active" else ("#fbbf24" if status_text == "recently_active" else "#64748b")

            is_blocked = d.get("blocked", False)
            if is_blocked:
                node_bg = "#991b1b"
                border_color = "#f87171"
                node_label = f"{hostname}\n{ip}\n[BLOCKED]"
                alloc_title = "INTERNET BLOCKED"
            else:
                node_bg = "#10b981" if is_online else "#475569"
                node_label = f"{hostname}\n{ip}"
                alloc_title = f"{allocated} Mbps allocated"

            dev_props = {
                "Type": "Client Device",
                "IP Address": ip,
                "MAC Address": d.get("mac", "Unknown"),
                "Hostname": hostname,
                "Discovery Status": status_text.replace("_", " ").title(),
                "Internet Access": "🚫 BLOCKED (Cut Off)" if is_blocked else "Allowed (Active)",
                "Latency": f"{d.get('latency_ms', '—')} ms" if d.get("latency_ms") is not None else "Unreachable",
                "Assigned Priority": prio,
                "Allocated Bandwidth": f"{allocated} Mbps" if not is_blocked else "0.0 Mbps (Blocked)",
                "Allocation Reason": expl_map.get(ip, "Default allocation"),
            }

            nodes.append({
                "id": dev_id,
                "label": node_label,
                "group": "device" if not is_blocked else "blocked",
                "shape": "dot",
                "size": 12 if is_online else 8,
                "color": {
                    "background": node_bg,
                    "border": border_color,
                },
                "font": {"color": "#e2e8f0", "size": 10},
                "properties": dev_props,
                "title": f"Device: {hostname} ({ip}) - {alloc_title}",
            })

            # Edge from Device to its Priority Class
            edges.append({
                "from": dev_id,
                "to": f"class:{prio}",
                "label": "MEMBER_OF",
                "arrows": "to",
                "color": {"color": "#64748b", "opacity": 0.4},
                "dashes": True,
            })

            # Edge from Core to Device representing Allocation
            if is_online and allocated > 0 and not is_blocked:
                edges.append({
                    "from": core_id,
                    "to": dev_id,
                    "label": f"{allocated}M",
                    "arrows": "to",
                    "color": {"color": "#2dd4bf", "opacity": 0.8},
                    "width": max(1, min(5, int(allocated / 5.0))),
                })

        # 5. NetworkX Graph Construction & Topologic Analytics
        nx_analytics = {}
        if NETWORKX_AVAILABLE:
            G = nx.MultiDiGraph()
            for node in nodes:
                G.add_node(
                    node["id"],
                    label=node.get("label", ""),
                    group=node.get("group", ""),
                    **node.get("properties", {})
                )
            for edge in edges:
                G.add_edge(
                    edge["from"],
                    edge["to"],
                    label=edge.get("label", ""),
                    relation=edge.get("label", "")
                )
            self.nx_graph = G

            try:
                centrality = nx.degree_centrality(G)
                density = round(float(nx.density(G)), 4)
                in_degrees = {k: int(v) for k, v in G.in_degree()}
                out_degrees = {k: int(v) for k, v in G.out_degree()}

                # Enrich node inspector properties with NetworkX centrality
                for node in nodes:
                    nid = node["id"]
                    if nid in centrality:
                        node["properties"]["NetworkX Centrality"] = f"{centrality[nid]:.3f}"
                        node["properties"]["In-Degree / Out-Degree"] = f"{in_degrees.get(nid, 0)} / {out_degrees.get(nid, 0)}"

                nx_analytics = {
                    "engine": "NetworkX Graph Engine",
                    "total_nodes": G.number_of_nodes(),
                    "total_edges": G.number_of_edges(),
                    "density": density,
                    "degree_centrality": {k: round(v, 3) for k, v in centrality.items()},
                    "topological_structure": "Hierarchical MultiDiGraph (Interface -> Core -> Classes -> Devices)",
                }
            except Exception as e:
                nx_analytics = {"engine": "NetworkX", "error": str(e)}

            self.last_analytics = nx_analytics

        return {"nodes": nodes, "edges": edges, "nx_analytics": nx_analytics}

    def get_summary(self) -> Dict[str, Any]:
        """Return diagnostic metrics of the NetworkX knowledge graph."""
        return {
            "networkx_available": NETWORKX_AVAILABLE,
            "analytics": self.last_analytics,
            "node_count": self.nx_graph.number_of_nodes() if self.nx_graph else 0,
            "edge_count": self.nx_graph.number_of_edges() if self.nx_graph else 0,
        }


global_knowledge_graph = NetworkKnowledgeGraph()
