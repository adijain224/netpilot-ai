"""
NetPilot AI — Configuration Module
==================================
Centralized configuration parameters, system constants, and validation helpers.
"""

import os
import re
import socket
import subprocess
import ipaddress
import time
from typing import Dict, Any, List, Set, Tuple

import psutil

# Base Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
TRAFFIC_CSV = os.path.join(DATA_DIR, "traffic_history.csv")

# Traffic Categories and QoS Priority Levels
TRAFFIC_CATEGORIES = {
    "High": {
        "label": "High (VoIP/Gaming/Real-Time)",
        "color": "#2DD4BF",       # Cyan
        "default_weight": 3.0,
        "min_share_pct": 20.0,
    },
    "Normal": {
        "label": "Normal (Web/Cloud/Streaming)",
        "color": "#60A5FA",       # Blue
        "default_weight": 1.5,
        "min_share_pct": 15.0,
    },
    "Low": {
        "label": "Low (Bulk Downloads/IoT)",
        "color": "#FBBF24",       # Amber
        "default_weight": 0.5,
        "min_share_pct": 5.0,
    },
    "Unknown": {
        "label": "Unknown / Unclassified",
        "color": "#94A3B8",       # Slate Gray
        "default_weight": 1.0,
        "min_share_pct": 10.0,
    },
}

# Legacy category mapping for backward-compatibility with existing views
LEGACY_CATEGORY_MAP = {
    "Video Conferencing": "High",
    "Cloud/Web": "Normal",
    "Streaming": "Normal",
    "Downloads": "Low",
    "IoT/Other": "Low",
    "High": "High",
    "Normal": "Normal",
    "Low": "Low",
    "Unknown": "Unknown",
}

# Default System Configuration
DEFAULT_CONFIG = {
    "capacity_mbps": 50.0,            # Total bandwidth capacity (Mbps)
    "poll_seconds": 2.5,              # Polling cycle interval
    "interface": None,                # Auto-detected or user selected
    "capture_interface": None,        # Scapy/Npcap sniff adapter
    "demo_mode": False,               # When True, generates simulated traffic/devices
    "enforcement_mode": "simulation", # Options: "simulation", "windows_qos", "router_linux_tc"
    "admin_authorized": False,        # Explicit authorization requirement for privileged enforcement
    "min_bandwidth_per_device": 0.5,  # Guarantee at least 0.5 Mbps for active devices
    "congestion_threshold_high": 0.85,# 85% capacity usage triggers HIGH congestion state
    "congestion_threshold_med": 0.50, # 50% capacity usage triggers MEDIUM congestion state
}

# Active Global Config Instance
CONFIG = dict(DEFAULT_CONFIG)


def validate_capacity(val):
    """Validate that capacity is a positive float."""
    try:
        f = float(val)
        if f <= 0:
            return False, "Capacity must be strictly positive."
        if f > 100000:
            return False, "Capacity exceeds realistic interface limits (100 Gbps)."
        return True, f
    except (TypeError, ValueError):
        return False, "Capacity must be a numeric value."


def validate_ip(ip_str):
    """Validate an IPv4 address string."""
    try:
        ip_obj = ipaddress.ip_address(str(ip_str).strip())
        if ip_obj.version != 4:
            return False, "Only IPv4 addresses are currently supported."
        return True, str(ip_obj)
    except ValueError:
        return False, f"Invalid IPv4 address: {ip_str}"


def validate_rate_limit(val):
    """Validate a bandwidth rate limit in Mbps."""
    try:
        f = float(val)
        if f < 0.1:
            return False, "Rate limit must be at least 0.1 Mbps."
        if f > 10000:
            return False, "Rate limit cannot exceed 10,000 Mbps."
        return True, round(f, 2)
    except (TypeError, ValueError):
        return False, "Rate limit must be numeric."


_GW_CACHE: Tuple[Set[str], Set[str]] = (set(), set())
_GW_CACHE_TIME: float = 0.0

def get_system_gateways_and_local_ips() -> Tuple[Set[str], Set[str]]:
    """
    Query the operating system for all default gateways and local host IP addresses.
    Crucial for distinguishing real client devices from upstream routers or the host PC itself.
    Cached for 15 seconds to keep packet callbacks and scan loops lightweight and responsive.
    """
    global _GW_CACHE, _GW_CACHE_TIME
    now = time.time()
    if _GW_CACHE[0] and (now - _GW_CACHE_TIME < 15.0):
        return _GW_CACHE

    gateways: Set[str] = set()
    local_ips: Set[str] = {"127.0.0.1"}

    # 1. Local host IPs via psutil
    try:
        for iface_name, addr_list in psutil.net_if_addrs().items():
            for a in addr_list:
                if a.family == socket.AF_INET and a.address:
                    local_ips.add(a.address)
    except Exception:
        pass

    # 2. Local IPs via PowerShell / netsh fallback
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", "Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress"],
            text=True, stderr=subprocess.DEVNULL, timeout=4
        )
        for line in out.splitlines():
            ip = line.strip()
            if ip and not ip.startswith("127."):
                local_ips.add(ip)
    except Exception:
        pass

    # 3. Default Gateway route via PowerShell
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop"],
            text=True, stderr=subprocess.DEVNULL, timeout=4
        )
        for line in out.splitlines():
            gw = line.strip()
            if gw and gw != "0.0.0.0":
                gateways.add(gw)
    except Exception:
        pass

    # 4. Fallback default gateway parsing via route print
    if not gateways:
        try:
            out = subprocess.check_output(["route", "print", "0.0.0.0"], text=True, stderr=subprocess.DEVNULL, timeout=4)
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw = parts[2]
                    if gw != "0.0.0.0" and gw not in local_ips:
                        gateways.add(gw)
        except Exception:
            pass

    _GW_CACHE = (gateways, local_ips)
    _GW_CACHE_TIME = now
    return gateways, local_ips
