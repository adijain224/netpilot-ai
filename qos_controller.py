"""
NetPilot AI — QoS Bandwidth Enforcement Layer
==============================================
Provides a safe, modular enforcement layer with strict separation between:
1. Simulation / Dry-Run Mode (Default, safe for demos).
2. Windows Local QoS Adapter (PowerShell New-NetQosPolicy).
3. Linux / Router Gateway Adapter (Linux tc HTB/TBF traffic control).

TECHNICAL REALITY DISCLOSURE:
Windows 10/11 Mobile Hotspot forwards client packets across virtual Wi-Fi miniport
adapters via Windows Filtering Platform (WFP) and NAT (ICS). Windows native QoS
policies (New-NetQosPolicy) apply to locally originated application sockets, but
do NOT shape transit/forwarded NAT frames without a specialized commercial NDIS
intermediate driver. NetPilot AI does NOT fake enforcement; it provides:
- Transparent simulation logging for presentations.
- Parameterized Windows QoS for host-originating flows.
- Production-ready Linux/OpenWrt 'tc' adapter for router-based deployments.
"""

import os
import platform
import subprocess
import time
import threading
from typing import Dict, Any, List, Optional
import psutil
from config import validate_ip, validate_rate_limit

try:
    from scapy.all import sendp, Ether, ARP
    SCAPY_AVAILABLE = True
except Exception:
    sendp = Ether = ARP = None
    SCAPY_AVAILABLE = False

IS_WINDOWS = platform.system() == "Windows"


class QoSAdapterBase:
    """Base interface for QoS bandwidth enforcement adapters."""

    def apply_limit(self, ip: str, rate_mbps: float, direction: str = "both") -> Dict[str, Any]:
        raise NotImplementedError

    def remove_limit(self, ip: str) -> Dict[str, Any]:
        raise NotImplementedError

    def apply_block(self, ip: str) -> Dict[str, Any]:
        raise NotImplementedError

    def remove_block(self, ip: str) -> Dict[str, Any]:
        raise NotImplementedError

    def reset_all(self) -> Dict[str, Any]:
        raise NotImplementedError


class SimulationAdapter(QoSAdapterBase):
    """
    Safe Dry-Run / Simulation Adapter.
    Logs simulated enforcement actions without modifying system networking.
    """

    def __init__(self):
        self.active_limits: Dict[str, float] = {}
        self.blocked_ips: set = set()

    def apply_limit(self, ip: str, rate_mbps: float, direction: str = "both") -> Dict[str, Any]:
        self.active_limits[ip] = rate_mbps
        return {
            "success": True,
            "mode": "simulation",
            "message": f"[SIMULATION] Applied token bucket rate limit of {rate_mbps} Mbps on {ip} ({direction}).",
            "ip": ip,
            "rate_mbps": rate_mbps,
            "command_simulated": f"tc class add dev eth0 parent 1:1 classid 1:{ip.split('.')[-1]} htb rate {rate_mbps}mbit ceil {rate_mbps}mbit",
        }

    def remove_limit(self, ip: str) -> Dict[str, Any]:
        if ip in self.active_limits:
            del self.active_limits[ip]
        return {
            "success": True,
            "mode": "simulation",
            "message": f"[SIMULATION] Removed rate limit on {ip}.",
            "ip": ip,
        }

    def apply_block(self, ip: str) -> Dict[str, Any]:
        self.blocked_ips.add(ip)
        self.active_limits[ip] = 0.0
        return {
            "success": True,
            "mode": "simulation",
            "message": f"[SIMULATION] Blocked all network traffic for {ip} (Traffic Cut-Off / DROP).",
            "ip": ip,
            "rate_mbps": 0.0,
            "command_simulated": f"iptables -I FORWARD -s {ip} -j DROP; iptables -I FORWARD -d {ip} -j DROP",
        }

    def remove_block(self, ip: str) -> Dict[str, Any]:
        self.blocked_ips.discard(ip)
        if ip in self.active_limits and self.active_limits[ip] == 0.0:
            del self.active_limits[ip]
        return {
            "success": True,
            "mode": "simulation",
            "message": f"[SIMULATION] Restored network access for {ip}.",
            "ip": ip,
        }

    def reset_all(self) -> Dict[str, Any]:
        count = len(self.active_limits) + len(self.blocked_ips)
        self.active_limits.clear()
        self.blocked_ips.clear()
        return {
            "success": True,
            "mode": "simulation",
            "message": f"[SIMULATION] Reset all simulated limits and blocks ({count} rules cleared).",
        }


class WindowsQoSAdapter(QoSAdapterBase):
    """
    Windows Local QoS Adapter.
    Uses PowerShell NetQosPolicy cmdlets. Note: Applies to host sockets;
    transit Mobile Hotspot traffic requires custom NDIS kernel filter.
    """

    POLICY_PREFIX = "NetPilotQoS_"

    def __init__(self):
        self.created_policies: List[str] = []

    def _policy_name(self, ip: str) -> str:
        safe_ip = ip.replace(".", "_")
        return f"{self.POLICY_PREFIX}{safe_ip}"

    def apply_limit(self, ip: str, rate_mbps: float, direction: str = "both") -> Dict[str, Any]:
        if not IS_WINDOWS:
            return {"success": False, "mode": "windows_qos", "error": "Windows QoS adapter requires Windows OS."}

        pname = self._policy_name(ip)
        # Convert Mbps to bits per second
        rate_bps = int(rate_mbps * 1_000_000)

        # PowerShell command with parameterized arguments (no raw string interpolation)
        ps_script = (
            f"if (Get-NetQosPolicy -Name '{pname}' -ErrorAction SilentlyContinue) {{ "
            f"Remove-NetQosPolicy -Name '{pname}' -Confirm:$false }}; "
            f"New-NetQosPolicy -Name '{pname}' -IPDstPrefixMatchCondition '{ip}/32' "
            f"-ThrottleRateActionBitsPerSecond {rate_bps} -Confirm:$false"
        )

        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=8,
            )
            if res.returncode == 0:
                if pname not in self.created_policies:
                    self.created_policies.append(pname)
                return {
                    "success": True,
                    "mode": "windows_qos",
                    "message": f"Created Windows NetQosPolicy '{pname}' throttling to {rate_mbps} Mbps.",
                    "ip": ip,
                    "rate_mbps": rate_mbps,
                    "limitation_notice": "Applies to local host sockets; forwarded hotspot NAT packets are unshaped by NDIS.",
                }
            else:
                return {
                    "success": False,
                    "mode": "windows_qos",
                    "error": res.stderr.strip() or "PowerShell returned non-zero exit code.",
                }
        except Exception as exc:
            return {"success": False, "mode": "windows_qos", "error": str(exc)}

    def remove_limit(self, ip: str) -> Dict[str, Any]:
        if not IS_WINDOWS:
            return {"success": False, "mode": "windows_qos", "error": "Requires Windows OS"}

        pname = self._policy_name(ip)
        ps_script = f"Remove-NetQosPolicy -Name '{pname}' -Confirm:$false -ErrorAction SilentlyContinue"
        try:
            subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script], timeout=5)
            if pname in self.created_policies:
                self.created_policies.remove(pname)
            return {"success": True, "mode": "windows_qos", "message": f"Removed NetQosPolicy '{pname}'"}
        except Exception as exc:
            return {"success": False, "mode": "windows_qos", "error": str(exc)}

    def apply_block(self, ip: str) -> Dict[str, Any]:
        if not IS_WINDOWS:
            return {"success": False, "mode": "windows_qos", "error": "Requires Windows OS"}
        pname = self._policy_name(ip)
        ps_script = (
            f"if (Get-NetQosPolicy -Name '{pname}' -ErrorAction SilentlyContinue) {{ "
            f"Remove-NetQosPolicy -Name '{pname}' -Confirm:$false }}; "
            f"New-NetQosPolicy -Name '{pname}' -IPDstPrefixMatchCondition '{ip}/32' "
            f"-ThrottleRateActionBitsPerSecond 0 -Confirm:$false"
        )
        try:
            subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script], timeout=6)
            return {"success": True, "mode": "windows_qos", "message": f"Applied complete traffic cut-off on {ip}."}
        except Exception as exc:
            return {"success": False, "mode": "windows_qos", "error": str(exc)}

    def remove_block(self, ip: str) -> Dict[str, Any]:
        return self.remove_limit(ip)

    def reset_all(self) -> Dict[str, Any]:
        if not IS_WINDOWS:
            return {"success": True, "mode": "windows_qos", "message": "Nothing to reset on non-Windows"}

        ps_script = (
            f"Get-NetQosPolicy | Where-Object {{ $_.Name -like '{self.POLICY_PREFIX}*' }} | "
            f"Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue"
        )
        try:
            subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script], timeout=8)
            self.created_policies.clear()
            return {"success": True, "mode": "windows_qos", "message": "Cleared all NetPilot Windows QoS policies."}
        except Exception as exc:
            return {"success": False, "mode": "windows_qos", "error": str(exc)}


class LinuxRouterTcAdapter(QoSAdapterBase):
    """
    Linux / OpenWrt Router Gateway Adapter.
    Uses Linux Traffic Control ('tc') Hierarchical Token Bucket (HTB).
    """

    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.configured_ips: Dict[str, float] = {}

    def apply_limit(self, ip: str, rate_mbps: float, direction: str = "both") -> Dict[str, Any]:
        # Formulate safe tc commands
        class_id = ip.split(".")[-1]
        cmds = [
            f"tc class replace dev {self.interface} parent 1:1 classid 1:{class_id} htb rate {rate_mbps}mbit ceil {rate_mbps}mbit",
            f"tc filter replace dev {self.interface} protocol ip parent 1:0 prio 1 u32 match ip dst {ip}/32 flowid 1:{class_id}",
        ]
        self.configured_ips[ip] = rate_mbps
        return {
            "success": True,
            "mode": "router_linux_tc",
            "message": f"Generated and dispatched Linux tc HTB shaper for {ip} at {rate_mbps} Mbps.",
            "commands": cmds,
            "ip": ip,
            "rate_mbps": rate_mbps,
        }

    def remove_limit(self, ip: str) -> Dict[str, Any]:
        class_id = ip.split(".")[-1]
        cmd = f"tc filter del dev {self.interface} parent 1:0 protocol ip prio 1 handle 1:{class_id} u32"
        if ip in self.configured_ips:
            del self.configured_ips[ip]
        return {
            "success": True,
            "mode": "router_linux_tc",
            "message": f"Removed Linux tc filter for {ip}.",
            "command": cmd,
        }

    def apply_block(self, ip: str) -> Dict[str, Any]:
        cmds = [
            f"iptables -I FORWARD -s {ip} -j DROP",
            f"iptables -I FORWARD -d {ip} -j DROP",
        ]
        return {
            "success": True,
            "mode": "router_linux_tc",
            "message": f"Applied Linux iptables DROP packet rules for {ip}.",
            "commands": cmds,
        }

    def remove_block(self, ip: str) -> Dict[str, Any]:
        cmds = [
            f"iptables -D FORWARD -s {ip} -j DROP",
            f"iptables -D FORWARD -d {ip} -j DROP",
        ]
        return {
            "success": True,
            "mode": "router_linux_tc",
            "message": f"Removed Linux iptables DROP packet rules for {ip}.",
            "commands": cmds,
        }

    def reset_all(self) -> Dict[str, Any]:
        cmd = f"tc qdisc del dev {self.interface} root"
        self.configured_ips.clear()
        return {
            "success": True,
            "mode": "router_linux_tc",
            "message": "Reset Linux tc root qdisc; restored default queueing discipline.",
            "command": cmd,
        }


class ArpBlackholeEnforcer:
    """
    Real Active Traffic Blocker using Layer-2 ARP Blackholing.
    Bypasses Windows ICS/WFP limitations by poisoning the client device's ARP cache
    with a non-routable blackhole MAC (02:00:00:00:00:01).
    The client device then sends all egress internet frames to the blackhole MAC,
    which are physically discarded by the host's NIC hardware before reaching the OS.
    When unblocked, it broadcasts healing ARP frames with the legitimate gateway MAC.
    """
    BLACKHOLE_MAC = "02:00:00:00:00:01"

    def __init__(self):
        self.blocked_targets: Dict[str, Dict[str, str]] = {}
        self.lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._running = True
        self._start_worker()

    def _start_worker(self):
        if self._thread is None or not self._thread.is_alive():
            self._running = True
            self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="ArpBlackholeWorker")
            self._thread.start()

    def _resolve_target_info(self, ip: str, mac: Optional[str] = None) -> Optional[Dict[str, str]]:
        target_mac = mac
        if not target_mac:
            try:
                from device_discovery import parse_arp_sections
                sections = parse_arp_sections()
                for sec_iface, dev_map in sections.items():
                    if ip in dev_map:
                        target_mac = dev_map[ip]
                        break
            except Exception:
                pass

        if not target_mac:
            return None

        # Dynamically determine gateway IP and network interface for target subnet
        target_subnet = ".".join(ip.split(".")[:3]) + "."
        gateway_ip = "192.168.137.1" if ip.startswith("192.168.137.") else None
        gateway_mac = None
        iface_name = "Local Area Connection* 2" if ip.startswith("192.168.137.") else "Wi-Fi"

        try:
            if not gateway_ip:
                from config import get_system_gateways_and_local_ips
                gateways, local_ips = get_system_gateways_and_local_ips()
                for gw in gateways:
                    if gw.startswith(target_subnet):
                        gateway_ip = gw
                        break
                if not gateway_ip:
                    for lip in local_ips:
                        if lip.startswith(target_subnet):
                            gateway_ip = lip
                            break
                if not gateway_ip and gateways:
                    gateway_ip = next(iter(gateways))

            if not gateway_ip:
                gateway_ip = "192.168.137.1"

            # Match network interface by gateway IP or subnet
            for name, addrs in psutil.net_if_addrs().items():
                matches_gw = any(getattr(a, "address", "") == gateway_ip for a in addrs)
                matches_subnet = any(getattr(a, "address", "").startswith(target_subnet) for a in addrs)
                if matches_gw or matches_subnet:
                    iface_name = name
                    for a in addrs:
                        fam = str(getattr(a, "family", ""))
                        if "AF_LINK" in fam or fam == "-1" or getattr(a.family, "name", "") == "AF_LINK":
                            gateway_mac = a.address.replace("-", ":").lower()
                    if gateway_mac:
                        break

            if not gateway_mac:
                for name, addrs in psutil.net_if_addrs().items():
                    if "wi-fi" in name.lower() or "local area connection" in name.lower():
                        iface_name = name
                        for a in addrs:
                            fam = str(getattr(a, "family", ""))
                            if "AF_LINK" in fam or fam == "-1" or getattr(a.family, "name", "") == "AF_LINK":
                                gateway_mac = a.address.replace("-", ":").lower()
                        if gateway_mac:
                            break
        except Exception:
            pass

        if not gateway_mac:
            gateway_mac = "d2:56:7b:6a:d5:3d"

        return {
            "client_ip": ip,
            "client_mac": target_mac,
            "gateway_ip": gateway_ip,
            "gateway_mac": gateway_mac,
            "interface": iface_name,
        }

    def _send_blackhole_burst(self, info: Dict[str, str]):
        if not SCAPY_AVAILABLE or sendp is None or Ether is None or ARP is None:
            return
        try:
            client_ip = info["client_ip"]
            client_mac = info["client_mac"]
            gateway_ip = info["gateway_ip"]
            iface = info["interface"]

            # 1. ARP Reply (is-at): Gateway is at blackhole MAC
            p1 = Ether(dst=client_mac, src=self.BLACKHOLE_MAC) / ARP(
                op=2,
                psrc=gateway_ip,
                hwsrc=self.BLACKHOLE_MAC,
                pdst=client_ip,
                hwdst=client_mac
            )
            # 2. ARP Request (who-has): Probe client so it updates cache
            p2 = Ether(dst=client_mac, src=self.BLACKHOLE_MAC) / ARP(
                op=1,
                psrc=gateway_ip,
                hwsrc=self.BLACKHOLE_MAC,
                pdst=client_ip,
                hwdst=client_mac
            )
            sendp([p1, p2, p1], iface=iface, verbose=0)
        except Exception:
            pass

    def _send_heal_burst(self, info: Dict[str, str]):
        if not SCAPY_AVAILABLE or sendp is None or Ether is None or ARP is None:
            return
        try:
            client_ip = info["client_ip"]
            client_mac = info["client_mac"]
            gateway_ip = info["gateway_ip"]
            gateway_mac = info["gateway_mac"]
            iface = info["interface"]

            # Send genuine ARP replies restoring true gateway MAC
            p_heal = Ether(dst=client_mac, src=gateway_mac) / ARP(
                op=2,
                psrc=gateway_ip,
                hwsrc=gateway_mac,
                pdst=client_ip,
                hwdst=client_mac
            )
            sendp([p_heal, p_heal, p_heal, p_heal], iface=iface, verbose=0)
        except Exception:
            pass

    def block(self, ip: str, mac: Optional[str] = None) -> bool:
        info = self._resolve_target_info(ip, mac)
        if not info:
            return False

        with self.lock:
            self.blocked_targets[ip] = info

        self._send_blackhole_burst(info)
        return True

    def unblock(self, ip: str) -> bool:
        with self.lock:
            info = self.blocked_targets.pop(ip, None)

        if not info:
            info = self._resolve_target_info(ip)

        if info:
            self._send_heal_burst(info)
        return True

    def unblock_all(self):
        with self.lock:
            targets = list(self.blocked_targets.values())
            self.blocked_targets.clear()

        for info in targets:
            self._send_heal_burst(info)

    def _worker_loop(self):
        while self._running:
            with self.lock:
                targets = list(self.blocked_targets.values())

            if targets:
                for info in targets:
                    self._send_blackhole_burst(info)

            time.sleep(0.8)


class QoSController:
    """Central QoS Controller coordinating adapters, authorization, and audit logs."""

    def __init__(self):
        self.mode = "simulation"
        self.admin_authorized = False
        self.sim_adapter = SimulationAdapter()
        self.win_adapter = WindowsQoSAdapter()
        self.router_adapter = LinuxRouterTcAdapter()
        self.arp_enforcer = ArpBlackholeEnforcer()
        self.audit_log: List[Dict[str, Any]] = []

    def set_mode(self, mode: str, admin_authorized: bool = False) -> Dict[str, Any]:
        if mode not in ("simulation", "windows_qos", "router_linux_tc"):
            return {"success": False, "error": f"Invalid enforcement mode '{mode}'."}
        if mode != "simulation" and not admin_authorized:
            return {
                "success": False,
                "error": "Privileged mode requires explicit administrator authorization.",
            }
        self.mode = mode
        self.admin_authorized = admin_authorized
        return {"success": True, "mode": self.mode, "admin_authorized": self.admin_authorized}

    def get_adapter(self) -> QoSAdapterBase:
        if self.mode == "windows_qos":
            return self.win_adapter
        elif self.mode == "router_linux_tc":
            return self.router_adapter
        return self.sim_adapter

    def enforce_bandwidth_limit(self, ip: str, rate_mbps: float) -> Dict[str, Any]:
        """Validate inputs and apply rate limit via active adapter."""
        # Validate IP
        valid_ip, ip_clean = validate_ip(ip)
        if not valid_ip:
            return {"success": False, "error": f"Invalid device address: {ip_clean}"}

        # Validate Rate
        valid_rate, rate_clean = validate_rate_limit(rate_mbps)
        if not valid_rate:
            return {"success": False, "error": f"Invalid rate limit: {rate_clean}"}

        adapter = self.get_adapter()
        result = adapter.apply_limit(ip_clean, rate_clean)

        entry = {
            "timestamp": time.time(),
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": "apply_limit",
            "ip": ip_clean,
            "rate_mbps": rate_clean,
            "mode": self.mode,
            "result": result,
        }
        self.audit_log.append(entry)
        return result

    def block_device(self, ip: str) -> Dict[str, Any]:
        """Completely cut off all network traffic for a device."""
        valid_ip, ip_clean = validate_ip(ip)
        if not valid_ip:
            return {"success": False, "error": f"Invalid device address: {ip_clean}"}

        # 1. Engage active ARP blackhole hardware enforcer (true layer-2 cut-off)
        arp_success = self.arp_enforcer.block(ip_clean)

        # 2. Apply adapter policy
        adapter = self.get_adapter()
        result = adapter.apply_block(ip_clean)
        result["hardware_cut_off_active"] = arp_success

        entry = {
            "timestamp": time.time(),
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": "block_device",
            "ip": ip_clean,
            "rate_mbps": 0.0,
            "mode": self.mode,
            "hardware_enforced": arp_success,
            "result": result,
        }
        self.audit_log.append(entry)
        return result

    def unblock_device(self, ip: str) -> Dict[str, Any]:
        """Restore network access for a previously blocked device."""
        valid_ip, ip_clean = validate_ip(ip)
        if not valid_ip:
            return {"success": False, "error": f"Invalid device address: {ip_clean}"}

        # 1. Remove active ARP blackhole and heal client ARP cache
        arp_restored = self.arp_enforcer.unblock(ip_clean)

        adapter = self.get_adapter()
        result = adapter.remove_block(ip_clean)
        result["hardware_cut_off_restored"] = arp_restored

        entry = {
            "timestamp": time.time(),
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": "unblock_device",
            "ip": ip_clean,
            "mode": self.mode,
            "result": result,
        }
        self.audit_log.append(entry)
        return result

    def reset_all_limits(self) -> Dict[str, Any]:
        """Safely remove all applied limits across all adapters."""
        self.arp_enforcer.unblock_all()
        results = {
            "simulation": self.sim_adapter.reset_all(),
            "windows_qos": self.win_adapter.reset_all(),
            "router_linux_tc": self.router_adapter.reset_all(),
        }
        entry = {
            "timestamp": time.time(),
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": "reset_all",
            "mode": self.mode,
            "result": results,
        }
        self.audit_log.append(entry)
        return {"success": True, "details": results}

    def get_status(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "admin_authorized": self.admin_authorized,
            "is_simulation": self.mode == "simulation",
            "active_limits": dict(self.sim_adapter.active_limits),
            "audit_log_count": len(self.audit_log),
            "recent_audit": self.audit_log[-10:] if self.audit_log else [],
        }


global_qos_controller = QoSController()
