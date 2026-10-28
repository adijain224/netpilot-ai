"""
NetPilot AI — Device Discovery Module
=====================================
Performs subnet-aware device discovery using system ARP cache parsing,
ICMP health checks, and network topology analysis.

Key engineering safeguards:
- Distinguishes connected client devices from upstream default gateways (e.g. 172.20.10.1)
  and local host adapter IP addresses (e.g. 192.168.137.1).
- Scopes discovery to the client-facing subnet (e.g. Windows Mobile Hotspot 192.168.137.0/24).
- Distinguishes 'confirmed_active' (ping/packet reachability) from 'discovered_only' (stale ARP).
- Maintains a diagnostic registry explaining why each network node was classified or excluded.
"""

import os
import platform
import re
import json
import socket
import subprocess
import time
import ipaddress
from typing import Dict, Any, Tuple, Optional, Set, List

from config import get_system_gateways_and_local_ips

IS_WINDOWS = platform.system() == "Windows"

_HOSTNAME_CACHE: Dict[str, str] = {}
_LAST_SEEN_CACHE: Dict[str, float] = {}

DEMO_DEVICES_TEMPLATE = [
    {"ip": "192.168.137.11", "mac": "a4:5e:60:11:2b:9c", "hostname": "Priyas-iPhone", "priority": "High"},
    {"ip": "192.168.137.12", "mac": "b8:27:eb:22:3a:5d", "hostname": "DESKTOP-GUEST7", "priority": "Normal"},
    {"ip": "192.168.137.13", "mac": "3c:5a:b4:44:1f:02", "hostname": "SmartTV-LivingRoom", "priority": "Normal"},
    {"ip": "192.168.137.14", "mac": "f0:18:98:77:6c:11", "hostname": "Rahuls-Laptop", "priority": "Low"},
]


def resolve_hostname(ip: str, timeout_s: float = 0.3) -> str:
    """Resolve IP to NetBIOS / DNS hostname with caching."""
    if ip in _HOSTNAME_CACHE:
        return _HOSTNAME_CACHE[ip]

    name = ip
    try:
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout_s)
        try:
            host_info = socket.gethostbyaddr(ip)
            if host_info and host_info[0]:
                name = host_info[0]
        finally:
            socket.setdefaulttimeout(orig_timeout)
    except Exception:
        name = ip

    _HOSTNAME_CACHE[ip] = name
    return name


def ping_host(ip: str, timeout_ms: int = 400) -> Tuple[bool, Optional[float]]:
    """
    Perform a single ICMP echo ping to verify if a device is confirmed active.
    Returns (is_active, latency_ms).
    """
    try:
        if IS_WINDOWS:
            ping_exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "PING.EXE")
            cmd = [ping_exe, "-n", "1", "-w", str(timeout_ms), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]

        out = subprocess.check_output(
            cmd,
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000.0) + 1.0,
        )

        m = re.search(r"time[=<]([\d.]+)\s*ms", out, re.IGNORECASE)
        if m:
            return True, float(m.group(1))

        if IS_WINDOWS and "Reply from" in out and "Destination host unreachable" not in out:
            return True, float(timeout_ms)

        return False, None
    except Exception:
        return False, None


def parse_arp_sections() -> Dict[str, Dict[str, str]]:
    """
    Parse the system ARP table section-by-section.
    Returns mapping: interface_ip -> {ip: mac_address}
    """
    sections: Dict[str, Dict[str, str]] = {}
    current_iface = "global"

    try:
        out = subprocess.check_output(
            ["arp", "-a"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )

        for line in out.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            # Check for Windows interface header, e.g. "Interface: 192.168.137.1 --- 0xb"
            iface_match = re.search(r"Interface:\s*([\d\.]+)", line_str, re.IGNORECASE)
            if iface_match:
                current_iface = iface_match.group(1)
                sections.setdefault(current_iface, {})
                continue

            # Match IP and MAC address entry
            m = re.search(r"(\b(?:\d{1,3}\.){3}\d{1,3}\b)\s+([0-9a-fA-F:-]{11,17})", line_str)
            if m:
                ip = m.group(1)
                mac = m.group(2).replace("-", ":").lower()

                # Filter broadcast, multicast, loopback, and dummy addresses
                octets = [int(x) for x in ip.split(".")]
                if (
                    octets[0] in (127, 224, 239, 255)
                    or octets[3] in (0, 255)
                    or mac.startswith("ff:ff:ff:ff:ff:ff")
                    or mac.startswith("00:00:00:00:00:00")
                    or mac.startswith("01:00:5e")
                ):
                    continue

                sections.setdefault(current_iface, {})[ip] = mac

    except Exception:
        pass

    return sections


def get_active_uplink_gateway() -> Optional[Dict[str, Any]]:
    """
    Identifies the single active router/device currently providing internet connectivity to this laptop.
    Queries the OS routing table for the lowest metric default route (0.0.0.0/0).
    Resolves hardware MAC address and connected Wi-Fi SSID when available.
    """
    gw_ip = None
    iface_name = "Wi-Fi"

    if IS_WINDOWS:
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1 | Select-Object NextHop, InterfaceAlias) | ConvertTo-Json"
            ]
            res = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=4)
            data = json.loads(res)
            gw_ip = data.get("NextHop")
            iface_name = data.get("InterfaceAlias") or iface_name
        except Exception:
            pass

    # Fallback to route print
    if not gw_ip:
        try:
            out = subprocess.check_output(["route", "print", "0.0.0.0"], text=True, stderr=subprocess.DEVNULL, timeout=4)
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    if parts[2] != "0.0.0.0" and not parts[2].startswith("127."):
                        gw_ip = parts[2]
                        break
        except Exception:
            pass

    if not gw_ip:
        return None

    # Resolve hardware MAC from system ARP
    mac = "Unknown"
    try:
        arp_out = subprocess.check_output(["arp", "-a", gw_ip], text=True, stderr=subprocess.DEVNULL, timeout=3)
        m = re.search(r"([0-9a-fA-F:-]{11,17})", arp_out)
        if m:
            mac = m.group(1).replace("-", ":").lower()
    except Exception:
        pass

    # Query active Wi-Fi SSID if wireless
    ssid = None
    if IS_WINDOWS and ("wi-fi" in iface_name.lower() or "wireless" in iface_name.lower()):
        try:
            wlan_out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], text=True, stderr=subprocess.DEVNULL, timeout=3)
            m_ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", wlan_out, re.MULTILINE)
            if m_ssid:
                ssid = m_ssid.group(1).strip()
        except Exception:
            pass

    hostname = f"Active Gateway ({gw_ip})"
    desc = f"Active Internet Router providing connection to this laptop via {iface_name}"
    if ssid:
        hostname = f"{ssid} (Uplink Router)"
        desc = f"Connected Wi-Fi Uplink Network ({ssid}) providing Internet to this laptop"

    return {
        "ip": gw_ip,
        "mac": mac,
        "hostname": hostname,
        "role": "upstream_active_gateway",
        "status": "active_provider",
        "interface": iface_name,
        "is_active_uplink": True,
        "is_provider": True,
        "description": desc,
        "ssid": ssid,
    }


class DeviceTracker:
    """Manages subnet-aware client discovery, active status, priorities, roles, and diagnostics."""

    def __init__(self):
        self.device_priorities: Dict[str, str] = {}
        self.blocked_ips: Set[str] = set()
        self.custom_roles: Dict[str, str] = {}  # ip -> "upstream" | "client"
        self.upstream_devices: Dict[str, Dict[str, Any]] = {}
        self.confirmed_active_ips: Set[str] = set()
        self.diagnostic_registry: Dict[str, Dict[str, Any]] = {}
        self.client_facing_subnet: Optional[str] = None

    def set_priority(self, ip: str, priority: str) -> bool:
        if priority in ("High", "Normal", "Low"):
            self.device_priorities[ip] = priority
            return True
        return False

    def get_priority(self, ip: str, default: str = "Normal") -> str:
        return self.device_priorities.get(ip, default)

    def block_device(self, ip: str, blocked: bool = True) -> bool:
        """Completely cut off / restore internet access for an IP address."""
        if blocked:
            self.blocked_ips.add(ip)
        else:
            self.blocked_ips.discard(ip)
        return True

    def unblock_device(self, ip: str) -> bool:
        """Restore internet access for an IP address."""
        return self.block_device(ip, False)

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def is_device_blocked(self, ip: str) -> bool:
        return self.is_blocked(ip)

    def set_device_role(self, ip: str, role: str) -> bool:
        """Designate device as 'client' or 'upstream' (internet source/gateway)."""
        if role in ("client", "upstream"):
            self.custom_roles[ip] = role
            if role == "upstream":
                self.upstream_devices[ip] = {
                    "ip": ip,
                    "mac": "Manual/Hotspot Upstream",
                    "hostname": f"Upstream Source ({ip})",
                    "role": "upstream_manual",
                    "status": "active_provider",
                    "interface": "Uplink Interface",
                    "is_provider": True,
                    "description": "Internet Provider designated by administrator",
                }
            else:
                self.upstream_devices.pop(ip, None)
            return True
        return False

    def get_device_role(self, ip: str) -> str:
        return self.custom_roles.get(ip, "client")

    def get_upstream_devices(self) -> List[Dict[str, Any]]:
        # Strictly filter and return ONLY the active device/router currently providing internet to this laptop
        active = [d for d in self.upstream_devices.values() if d.get("is_active_uplink")]
        if active:
            return active[:1]
        active_status = [d for d in self.upstream_devices.values() if d.get("status") == "active_provider"]
        if active_status:
            return active_status[:1]
        return list(self.upstream_devices.values())[:1]

    def scan_network(
        self,
        demo_mode: bool = False,
        tick: int = 1,
        preferred_subnet: Optional[str] = None,
        observed_packet_ips: Optional[Set[str]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Scan and return a verified dictionary of connected client devices.
        Excludes upstream default gateways and local host addresses.
        """
        now = time.time()
        self.diagnostic_registry.clear()
        self.upstream_devices.clear()

        # Step 1: Query system gateways and local host IPs
        gateways, local_ips = get_system_gateways_and_local_ips()

        for gw in gateways:
            self.diagnostic_registry[gw] = {
                "ip": gw,
                "classification": "gateway",
                "is_client": False,
                "reason": "Excluded: Upstream default gateway / internet router",
            }
        for lip in local_ips:
            self.diagnostic_registry[lip] = {
                "ip": lip,
                "classification": "local_host",
                "is_client": False,
                "reason": "Excluded: Local host PC adapter address",
            }

        # Step 1b: Strictly detect and register ONLY the active router/device providing internet to this laptop
        active_gw = get_active_uplink_gateway()
        if active_gw:
            self.upstream_devices[active_gw["ip"]] = active_gw
        elif gateways:
            # Fallback if active route check returned None
            primary_gw = next(iter(gateways))
            self.upstream_devices[primary_gw] = {
                "ip": primary_gw,
                "mac": "Gateway / Router",
                "hostname": "Default Gateway (Internet Provider)",
                "role": "upstream_active_gateway",
                "status": "active_provider",
                "interface": "Uplink Interface",
                "is_active_uplink": True,
                "is_provider": True,
                "description": "Primary Default Gateway providing Internet to this laptop",
            }

        # Step 2: Parse ARP table sections
        arp_sections = parse_arp_sections()

        # Determine target client subnet:
        # If any ARP section has an interface IP starting with 192.168.137.
        hotspot_iface = None
        for iface_ip in arp_sections:
            if iface_ip.startswith("192.168.137."):
                hotspot_iface = iface_ip
                break

        # Fallback simulation if requested
        if demo_mode or (not arp_sections and os.environ.get("DEMO_MODE") == "1"):
            sim_devices = {}
            for item in DEMO_DEVICES_TEMPLATE:
                ip = item["ip"]
                priority = self.get_priority(ip, item["priority"])
                sim_devices[ip] = {
                    "ip": ip,
                    "mac": item["mac"],
                    "hostname": item["hostname"],
                    "online": True,
                    "status": "confirmed_active",
                    "latency_ms": 14.0 + (hash(ip) % 20),
                    "priority": priority,
                    "last_seen": now,
                    "is_simulated": True,
                    "device_type": "client",
                }
                self.diagnostic_registry[ip] = {
                    "ip": ip,
                    "classification": "client",
                    "is_client": True,
                    "reason": "Simulated demonstration client",
                }
            return sim_devices

        # Step 3: Filter candidates
        # If hotspot interface exists, only accept devices from the hotspot section
        candidate_entries: Dict[str, Tuple[str, str]] = {}  # ip -> (mac, iface_section)

        if hotspot_iface and hotspot_iface in arp_sections:
            self.client_facing_subnet = "192.168.137.0/24"
            for ip, mac in arp_sections[hotspot_iface].items():
                candidate_entries[ip] = (mac, hotspot_iface)
            # Log excluded non-hotspot sections
            for iface_ip, entries in arp_sections.items():
                if iface_ip != hotspot_iface:
                    for ip in entries:
                        if ip not in candidate_entries:
                            is_gw = ip in gateways
                            self.diagnostic_registry[ip] = {
                                "ip": ip,
                                "mac": entries[ip],
                                "classification": "gateway" if is_gw else "uplink_host",
                                "is_client": False,
                                "reason": "Excluded: Upstream default gateway" if is_gw else f"Excluded: Host sits on upstream/external interface {iface_ip}, not hotspot client subnet",
                            }
        else:
            # No hotspot section; accept non-gateway, non-local entries across interfaces
            self.client_facing_subnet = "local"
            for iface_ip, entries in arp_sections.items():
                for ip, mac in entries.items():
                    if ip not in gateways and ip not in local_ips:
                        candidate_entries[ip] = (mac, iface_ip)
                    else:
                        reason = "Excluded: Default gateway" if ip in gateways else "Excluded: Local host IP"
                        self.diagnostic_registry[ip] = {
                            "ip": ip,
                            "mac": mac,
                            "classification": "gateway" if ip in gateways else "local_host",
                            "is_client": False,
                            "reason": reason,
                        }

        # Also incorporate any observed packet IPs from the sniffer that are on the client subnet
        if observed_packet_ips:
            for ip in observed_packet_ips:
                if (
                    ip not in candidate_entries
                    and ip not in gateways
                    and ip not in local_ips
                    and not ip.startswith("127.")
                    and (not hotspot_iface or ip.startswith("192.168.137."))
                ):
                    candidate_entries[ip] = ("unknown_mac", "packet_sniff")

        # Step 4: Verify client reachability and build client dictionary
        client_devices: Dict[str, Dict[str, Any]] = {}

        for ip, (mac, source_iface) in candidate_entries.items():
            # Strict safety check: never include gateway or local IP as a client
            if ip in gateways:
                self.diagnostic_registry[ip] = {
                    "ip": ip, "mac": mac, "classification": "gateway", "is_client": False,
                    "reason": "Excluded: Upstream default gateway route (NextHop)",
                }
                continue
            if ip in local_ips:
                self.diagnostic_registry[ip] = {
                    "ip": ip, "mac": mac, "classification": "local_host", "is_client": False,
                    "reason": "Excluded: Matches local host network adapter IP",
                }
                continue

            hostname = resolve_hostname(ip)

            # Check if this device is an Upstream Internet Provider (e.g. tethered iPhone giving internet to PC)
            is_explicit_upstream = self.custom_roles.get(ip) == "upstream"
            is_auto_iphone_tether = (
                self.custom_roles.get(ip) != "client"
                and "iphone" in (hostname or "").lower()
                and any(gw.startswith("172.20.10.") or gw == "172.20.10.1" for gw in gateways)
            )

            if is_explicit_upstream or is_auto_iphone_tether:
                self.upstream_devices[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "role": "upstream_tether",
                    "status": "active_tether_source",
                    "interface": source_iface,
                    "is_provider": True,
                    "description": "iPhone Internet Source Providing Hotspot/Tethering to PC",
                }
                self.diagnostic_registry[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "classification": "upstream_provider",
                    "is_client": False,
                    "reason": "Classified as Upstream Internet Provider (providing internet to PC; excluded from client quotas)",
                }
                continue

            online, latency = ping_host(ip, timeout_ms=300)

            # Did we see recent packets from this host?
            has_recent_packets = bool(observed_packet_ips and ip in observed_packet_ips)

            if online or has_recent_packets:
                status = "confirmed_active"
                online = True
                self.confirmed_active_ips.add(ip)
                _LAST_SEEN_CACHE[ip] = now
            elif (now - _LAST_SEEN_CACHE.get(ip, 0)) < 15.0:
                # Device missed ping and has no recent Tx traffic; show as inactive
                status = "inactive"
                online = False
                self.confirmed_active_ips.discard(ip)
            else:
                status = "offline"
                online = False
                self.confirmed_active_ips.discard(ip)
                # If device is confirmed disconnected (>15s without ping or Tx traffic),
                # drop it completely from the connected devices list so phantom devices disappear
                self.diagnostic_registry[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "classification": "disconnected_client",
                    "is_client": False,
                    "status": "offline",
                    "reason": f"Device unpingable and no Tx packets detected on {source_iface} for >15s",
                }
                continue

            priority = self.get_priority(ip, "Normal")
            is_blocked = self.is_blocked(ip)
            if is_blocked:
                status = "blocked"

            client_devices[ip] = {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "online": online and not is_blocked,
                "blocked": is_blocked,
                "status": status,
                "latency_ms": latency if not is_blocked else None,
                "priority": priority,
                "last_seen": _LAST_SEEN_CACHE.get(ip, now),
                "is_simulated": False,
                "device_type": "client",
                "source_interface": source_iface,
            }

            self.diagnostic_registry[ip] = {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "classification": "client",
                "is_client": True,
                "status": status,
                "reason": f"Verified client connected via {source_iface}",
            }

        return client_devices

    def get_diagnostics(self) -> Dict[str, Any]:
        """Return diagnostic view of all observed IPs and why each was included/excluded."""
        gateways, local_ips = get_system_gateways_and_local_ips()
        return {
            "client_facing_subnet": self.client_facing_subnet,
            "detected_gateways": list(gateways),
            "detected_local_ips": list(local_ips),
            "all_entities": self.diagnostic_registry,
        }


global_device_tracker = DeviceTracker()
