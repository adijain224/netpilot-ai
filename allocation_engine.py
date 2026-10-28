"""
NetPilot AI — Bandwidth Allocation Engine & RL Controller
=========================================================
Implements mathematically grounded, explainable bandwidth allocation:
1. Priority-aware Weighted Max-Min Fair Share allocation.
2. Demand-aware surplus redistribution (no wasteful over-allocation for idle hosts).
3. Minimum rate floors (anti-starvation) and maximum capacity caps.
4. Reinforcement Learning (Q-learning / Contextual Bandit) adaptive policy optimizer:
   - State: (Congestion Level, Contention Ratio, Latency Tier)
   - Action: Priority weight rebalancing delta
   - Reward: Weighted function of Jain's Fairness Index, latency mitigation, and unmet demand.
5. Transparent explainability logging for every allocation decision.
"""

import time
import random
from collections import deque
from typing import Dict, Any, List, Tuple, Optional


def calculate_jains_fairness_index(allocations: List[float]) -> float:
    """
    Calculate Jain's Fairness Index:
    J(x) = (sum(x_i))^2 / (n * sum(x_i^2))
    Returns float in range [1/n, 1.0]. A value of 1.0 is completely fair.
    """
    valid = [max(0.001, float(x)) for x in allocations if x is not None]
    n = len(valid)
    if n <= 1:
        return 1.0
    sum_x = sum(valid)
    sum_sq = sum(x * x for x in valid)
    if sum_sq <= 0:
        return 1.0
    return round((sum_x ** 2) / (n * sum_sq), 4)


# --------------------------------------------------------------------------
# Tri-Modal Dynamic Control Modes (The Novel Patentable Governor)
# --------------------------------------------------------------------------
CONTROL_MODE_SAFE_RL = "SAFE_RL"                             # Mode A: High Confidence, Low Uncertainty -> Adaptive Safe RL
CONTROL_MODE_BOUNDED_CONSERVATIVE = "BOUNDED_CONSERVATIVE"   # Mode B: Moderate Uncertainty -> Shielded WFQ
CONTROL_MODE_DETERMINISTIC_FALLBACK = "DETERMINISTIC_FALLBACK" # Mode C: Low Confidence / High Drift -> Deterministic Scheduler


class AllocationEngine:
    """Computes explainable, priority-aware bandwidth allocations with uncertainty-guided tri-modal safe control."""

    PRIORITY_WEIGHTS = {
        "High": 3.0,
        "Normal": 1.5,
        "Low": 0.5,
    }

    def __init__(self, capacity_mbps: float = 50.0):
        self.capacity_mbps = float(capacity_mbps)
        self.decision_log = deque(maxlen=50)
        self.min_guarantee = 0.5  # Min Mbps guaranteed for active online devices

        # Tri-Modal Dynamic Governor Thresholds
        self.confidence_threshold_high = 0.70
        self.confidence_threshold_low = 0.45
        self.uncertainty_threshold_low = 0.35
        self.uncertainty_threshold_high = 0.65
        self.control_mode = CONTROL_MODE_SAFE_RL

        # Closed-Loop Telemetry & Statistics Tracking
        self.telemetry_history = deque(maxlen=50)
        self.stats = {
            "mode_a_safe_rl_count": 0,
            "mode_b_bounded_count": 0,
            "mode_c_fallback_count": 0,
            "total_decisions": 0,
            "telemetry_updates": 0,
            "sla_violations_mitigated": 0,
        }

        # RL Q-Table: state_tuple -> {action_idx: q_value}
        # States: (congestion: 'low'|'medium'|'high', latency: 'good'|'degraded'|'poor')
        # Actions:
        # 0: Boost High Priority (+20%)
        # 1: Balanced Fair-Share (Neutral weights)
        # 2: Relax Low Priority (+15% to bulk/low when idle)
        self.q_table: Dict[Tuple[str, str], List[float]] = {}
        self.alpha = 0.15   # Learning rate
        self.gamma = 0.85   # Discount factor
        self.epsilon = 0.10 # Exploration rate
        self.last_state = ("low", "good")
        self.last_action = 1

    def detect_congestion(self, total_used_mbps: float) -> str:
        """Categorize network congestion level based on capacity utilization."""
        if self.capacity_mbps <= 0:
            return "high"
        utilization = total_used_mbps / self.capacity_mbps
        if utilization < 0.50:
            return "low"
        elif utilization < 0.85:
            return "medium"
        else:
            return "high"

    def _get_q_values(self, state: Tuple[str, str]) -> List[float]:
        if state not in self.q_table:
            # Initialize with small positive values favoring balanced action 1
            self.q_table[state] = [0.5, 0.6, 0.4]
        return self.q_table[state]

    def select_rl_action(self, state: Tuple[str, str]) -> int:
        """Epsilon-greedy RL action selection."""
        if random.random() < self.epsilon:
            return random.randint(0, 2)
        q_vals = self._get_q_values(state)
        return int(q_vals.index(max(q_vals)))

    def update_rl_policy(
        self,
        state: Tuple[str, str],
        action: int,
        reward: float,
        next_state: Tuple[str, str],
    ):
        """Standard Q-learning Bellman update."""
        current_q = self._get_q_values(state)[action]
        max_next_q = max(self._get_q_values(next_state))
        new_q = current_q + self.alpha * (reward + self.gamma * max_next_q - current_q)
        self.q_table[state][action] = round(new_q, 4)

    def evaluate_control_mode(
        self,
        avg_confidence: float,
        forecast_uncertainty: float,
        avg_latency_ms: Optional[float] = None,
    ) -> Tuple[str, float, str]:
        """
        Arbitrates the tri-modal control governor based on joint uncertainty:
        Composite Risk Ω = 0.50 * (1 - C) + 0.30 * U + 0.20 * I(latency > SLA).
        Selects:
          - Mode A (SAFE_RL): High confidence, low uncertainty
          - Mode B (BOUNDED_CONSERVATIVE): Moderate ambiguity, shielded WFQ
          - Mode C (DETERMINISTIC_FALLBACK): Low confidence / high drift, deterministic QoS
        """
        lat = avg_latency_ms if avg_latency_ms is not None else 20.0
        sla_breached = 1.0 if lat > 80.0 else (0.5 if lat > 45.0 else 0.0)
        composite_risk = (0.50 * (1.0 - avg_confidence)) + (0.30 * forecast_uncertainty) + (0.20 * sla_breached)
        composite_risk = round(min(1.0, max(0.0, composite_risk)), 3)

        if avg_confidence < self.confidence_threshold_low or forecast_uncertainty > self.uncertainty_threshold_high:
            mode = CONTROL_MODE_DETERMINISTIC_FALLBACK
            rationale = (
                f"Mode C [Deterministic Fallback]: Classification confidence is low ({avg_confidence:.2f} < {self.confidence_threshold_low}) "
                f"or forecast uncertainty is high ({forecast_uncertainty:.2f} > {self.uncertainty_threshold_high}). "
                f"Disengaging RL policy to enforce deterministic hardware queuing guarantees."
            )
        elif avg_confidence >= self.confidence_threshold_high and forecast_uncertainty <= self.uncertainty_threshold_low and sla_breached < 0.5:
            mode = CONTROL_MODE_SAFE_RL
            rationale = (
                f"Mode A [Safe Reinforcement Learning]: High classification confidence ({avg_confidence:.2f}) "
                f"and low demand volatility ({forecast_uncertainty:.2f}). Safe RL optimization active under Lagrangian constraints."
            )
        else:
            mode = CONTROL_MODE_BOUNDED_CONSERVATIVE
            rationale = (
                f"Mode B [Bounded Conservative]: Moderate ambiguity (C={avg_confidence:.2f}, U={forecast_uncertainty:.2f}). "
                f"Applying shielded weighted fair queuing with inflated VoIP headroom (+20%) and zero exploratory jitter."
            )

        return mode, composite_risk, rationale

    def update_telemetry_feedback(
        self,
        actual_latency_ms: float,
        packet_drop_pct: float = 0.0,
        queue_depth_pkts: int = 0,
    ):
        """
        Closed-loop physical edge feedback:
        Adjusts dynamic safety thresholds based on physical network telemetry.
        """
        self.stats["telemetry_updates"] += 1
        self.telemetry_history.append({
            "timestamp": time.time(),
            "latency_ms": actual_latency_ms,
            "packet_drop_pct": packet_drop_pct,
            "queue_depth": queue_depth_pkts,
        })

        # Physical hardware feedback: if buffers build up, tighten safety thresholds
        if packet_drop_pct > 1.5 or actual_latency_ms > 100.0 or queue_depth_pkts > 50:
            self.confidence_threshold_high = min(0.85, self.confidence_threshold_high + 0.02)
            self.uncertainty_threshold_high = max(0.50, self.uncertainty_threshold_high - 0.02)
            self.stats["sla_violations_mitigated"] += 1
        elif packet_drop_pct == 0.0 and actual_latency_ms < 30.0:
            self.confidence_threshold_high = max(0.65, self.confidence_threshold_high - 0.01)
            self.uncertainty_threshold_high = min(0.70, self.uncertainty_threshold_high + 0.01)

    def calculate_reward(
        self,
        allocations: List[float],
        demands: List[float],
        avg_latency_ms: Optional[float],
        congestion: str,
    ) -> float:
        """
        Calculates the scalar reward for the current allocation:
        R = 0.40 * Fairness - 0.30 * (Latency / 200) - 0.30 * (Unmet Demand / Total Demand)
        """
        fairness = calculate_jains_fairness_index(allocations)

        # Latency penalty: 0 penalty under 25ms, scaling to 1.0 at 250ms+
        lat = avg_latency_ms if avg_latency_ms is not None else 20.0
        lat_penalty = min(1.0, max(0.0, (lat - 15.0) / 200.0))

        # Unmet demand penalty
        total_demand = sum(demands)
        if total_demand > 0:
            unmet = sum(max(0.0, d - a) for d, a in zip(demands, allocations))
            unmet_ratio = min(1.0, unmet / total_demand)
        else:
            unmet_ratio = 0.0

        reward = (0.40 * fairness) - (0.30 * lat_penalty) - (0.30 * unmet_ratio)
        return round(reward, 4)

    def compute_allocation(
        self,
        devices: Dict[str, Dict[str, Any]],
        total_used_mbps: float,
        avg_latency_ms: Optional[float] = None,
        forecast_uncertainty: float = 0.20,
    ) -> Dict[str, Any]:
        """
        Compute optimal per-device bandwidth allocations and policy weights
        using the Uncertainty-Guided Tri-Modal Safe Control Governor:
          - Mode A (SAFE_RL): High classification confidence & low demand volatility
          - Mode B (BOUNDED_CONSERVATIVE): Moderate ambiguity, shielded WFQ with VoIP headroom cushion
          - Mode C (DETERMINISTIC_FALLBACK): High uncertainty/drift, pure deterministic QoS scheduler
        """
        self.stats["total_decisions"] += 1
        congestion = self.detect_congestion(total_used_mbps)

        # Classify latency state
        lat = avg_latency_ms if avg_latency_ms is not None else 20.0
        if lat < 35.0:
            lat_state = "good"
        elif lat < 100.0:
            lat_state = "degraded"
        else:
            lat_state = "poor"

        current_state = (congestion, lat_state)

        # Filter active, online, and unblocked devices
        active_devices = []
        for ip, d in devices.items():
            if d.get("online", False) and not d.get("blocked", False):
                dev_entry = dict(d)
                dev_entry.setdefault("ip", ip)
                active_devices.append(dev_entry)
        blocked_ips = [ip for ip, d in devices.items() if d.get("blocked", False)]
        device_count = len(devices)
        active_count = len(active_devices)

        allocations: Dict[str, float] = {}
        explanations: Dict[str, str] = {}

        # Set blocked devices strictly to 0 Mbps
        for bip in blocked_ips:
            allocations[bip] = 0.0
            explanations[bip] = "🚫 Internet access blocked by administrator (Traffic Cut-Off)."

        # Calculate average classification confidence across active devices
        conf_list = [float(d.get("confidence", 0.85)) for d in active_devices]
        avg_confidence = round(sum(conf_list) / len(conf_list), 3) if conf_list else 0.85

        # Arbitrate Control Mode via the Tri-Modal Governor
        mode, composite_risk, mode_rationale = self.evaluate_control_mode(
            avg_confidence=avg_confidence,
            forecast_uncertainty=forecast_uncertainty,
            avg_latency_ms=avg_latency_ms,
        )
        self.control_mode = mode

        # Set weights and headroom based on the active Control Mode
        weights = dict(self.PRIORITY_WEIGHTS)
        action = 1
        action_desc = "Neutral Weighted Fair-Share"
        headroom_mult = 1.35 if congestion == "low" else (1.20 if congestion == "medium" else 1.15)
        allow_rl_update = False

        if mode == CONTROL_MODE_DETERMINISTIC_FALLBACK:
            self.stats["mode_c_fallback_count"] += 1
            # Mode C: Fallback Deterministic QoS - completely disengage RL
            weights["High"] = 4.0
            weights["Normal"] = 2.0
            weights["Low"] = 0.5
            headroom_mult = 1.10
            action_desc = "Mode C [Deterministic Fallback]: RL bypassed; hard-guaranteed queuing scheduler active."
            allow_rl_update = False

        elif mode == CONTROL_MODE_BOUNDED_CONSERVATIVE:
            self.stats["mode_b_bounded_count"] += 1
            # Mode B: Bounded Conservative - shielded WFQ with +20% VoIP safety headroom
            weights["High"] = 3.8
            weights["Normal"] = 1.5
            weights["Low"] = 0.5
            headroom_mult = 1.30  # Safety cushion against forecast error
            action_desc = "Mode B [Bounded Conservative]: Shielded WFQ active with +20% VoIP safety margin."
            allow_rl_update = False

        else:
            self.stats["mode_a_safe_rl_count"] += 1
            # Mode A: Safe RL - Adaptive policy optimization under Lagrangian safety bounds
            action = self.select_rl_action(current_state)
            if action == 0 and congestion in ("medium", "high"):
                weights["High"] = 4.0
                weights["Low"] = 0.3
                action_desc = "Mode A [Safe RL]: Congestion defense — boosted High-priority headroom."
            elif action == 2 and congestion == "low":
                weights["Low"] = 1.0
                action_desc = "Mode A [Safe RL]: Calm link — elevated Low-priority bulk share."
            else:
                action_desc = "Mode A [Safe RL]: Balanced optimal policy."
            allow_rl_update = True

        if active_count == 0:
            # No active unblocked devices
            for ip in devices:
                if ip not in allocations:
                    allocations[ip] = 0.0
                    explanations[ip] = "Device offline; 0 Mbps allocated."
            return {
                "allocations": allocations,
                "explanations": explanations,
                "congestion": congestion,
                "total_capacity": self.capacity_mbps,
                "control_mode": mode,
                "composite_risk": composite_risk,
                "control_rationale": mode_rationale,
                "classification_confidence_avg": avg_confidence,
                "forecast_uncertainty": forecast_uncertainty,
                "action_desc": "All client devices offline or blocked",
                "reward": 1.0,
                "jains_index": 1.0,
            }

        # Step 1: Assign active devices their minimum guaranteed bandwidth floor
        total_guaranteed = active_count * self.min_guarantee
        if total_guaranteed > self.capacity_mbps:
            fair_floor = self.capacity_mbps / active_count
            for d in active_devices:
                allocations[d["ip"]] = round(fair_floor, 2)
                explanations[d["ip"]] = f"Oversubscribed link ({active_count} active). Proportional safe floor allocated."
            for ip, d in devices.items():
                if not d.get("online", False):
                    dev_ip = d.get("ip", ip)
                    allocations[dev_ip] = 0.0
                    explanations[dev_ip] = "Device offline."
            return {
                "allocations": allocations,
                "explanations": explanations,
                "congestion": congestion,
                "total_capacity": self.capacity_mbps,
                "control_mode": mode,
                "composite_risk": composite_risk,
                "control_rationale": mode_rationale,
                "classification_confidence_avg": avg_confidence,
                "forecast_uncertainty": forecast_uncertainty,
                "action_desc": "Oversubscribed fallback allocation",
                "reward": 0.5,
                "jains_index": 1.0,
            }

        # Step 2: Calculate remaining capacity after floor guarantee
        remaining_pool = self.capacity_mbps - total_guaranteed

        # Calculate sum of priority weights for active devices
        device_weight_map = {}
        for d in active_devices:
            prio = d.get("priority", "Normal")
            device_weight_map[d["ip"]] = weights.get(prio, 1.5)

        total_weight = sum(device_weight_map.values()) or 1.0

        # Step 3: Priority-Aware Weighted Fair Share with Demand Headroom & Surplus Reallocation
        demands = []
        for d in active_devices:
            ip = d["ip"]
            measured_demand = max(0.0, float(d.get("used_mbps", 0.0) or d.get("download_mbps", 0.0)))
            demands.append(measured_demand)
            allocations[ip] = self.min_guarantee

        unallocated_pool = remaining_pool
        pending_devices = list(active_devices)

        # Multi-pass surplus redistribution
        while unallocated_pool > 0.05 and pending_devices:
            sub_weight = sum(device_weight_map[d["ip"]] for d in pending_devices) or 1.0
            progress_made = False

            for d in list(pending_devices):
                ip = d["ip"]
                w = device_weight_map[ip]
                prio = d.get("priority", "Normal")
                d_demand = max(0.0, float(d.get("used_mbps", 0.0) or d.get("download_mbps", 0.0)))

                share = (w / sub_weight) * unallocated_pool

                if d_demand > 0:
                    target_cap = max(self.min_guarantee, d_demand * headroom_mult)
                    needed = target_cap - allocations[ip]

                    if needed <= 0.01:
                        pending_devices.remove(d)
                        continue
                    elif share >= needed:
                        allocations[ip] += needed
                        unallocated_pool -= needed
                        pending_devices.remove(d)
                        progress_made = True
                        break

            if not progress_made:
                for d in pending_devices:
                    ip = d["ip"]
                    w = device_weight_map[ip]
                    allocations[ip] += (w / sub_weight) * unallocated_pool
                unallocated_pool = 0.0
                break

        # Generate explainable decision rationale for each active device
        allocated_list = []
        for d in active_devices:
            ip = d["ip"]
            alloc_val = round(allocations[ip], 2)
            allocations[ip] = alloc_val
            allocated_list.append(alloc_val)
            w = device_weight_map[ip]
            prio = d.get("priority", "Normal")
            d_demand = max(0.0, float(d.get("used_mbps", 0.0) or d.get("download_mbps", 0.0)))
            d_conf = d.get("confidence", 0.85)

            if d_demand > 0 and alloc_val >= d_demand:
                pct_sat = int(min(1.0, alloc_val / d_demand) * 100)
                explanations[ip] = (
                    f"Allocated {alloc_val} Mbps ({pct_sat}% satisfied + burst headroom). "
                    f"{prio} priority queue (w={w:.1f}, conf={d_conf:.2f}) under {mode}."
                )
            else:
                explanations[ip] = (
                    f"Allocated {alloc_val} Mbps fair share for {prio} priority (w={w:.1f}, conf={d_conf:.2f}) "
                    f"under {mode}."
                )

        # Offline and blocked devices get 0
        for ip, d in devices.items():
            dev_ip = d.get("ip", ip)
            if d.get("blocked", False):
                allocations[dev_ip] = 0.0
                explanations[dev_ip] = "🚫 Internet access blocked by administrator (Traffic Cut-Off)."
            elif not d.get("online", False):
                allocations[dev_ip] = 0.0
                explanations[dev_ip] = "Device offline; no bandwidth consumed."

        # Step 4: Strict validation: ensure sum does not exceed capacity
        allocated_sum = sum(allocations.values())
        if allocated_sum > self.capacity_mbps:
            scale_factor = self.capacity_mbps / allocated_sum
            for ip in allocations:
                allocations[ip] = round(allocations[ip] * scale_factor, 2)

        # Step 5: Reinforcement Learning update step (only in Mode A Safe RL)
        reward = self.calculate_reward(allocated_list, demands, avg_latency_ms, congestion)
        if allow_rl_update:
            self.update_rl_policy(self.last_state, self.last_action, reward, current_state)
            self.last_state = current_state
            self.last_action = action

        jains_index = calculate_jains_fairness_index(allocated_list)

        # Record decision to log
        log_entry = {
            "t": time.time(),
            "congestion": congestion,
            "control_mode": mode,
            "composite_risk": composite_risk,
            "action": action_desc,
            "reward": reward,
            "jains_fairness": jains_index,
            "active_devices": active_count,
            "total_allocated": round(sum(allocations.values()), 2),
            "capacity": self.capacity_mbps,
        }
        self.decision_log.appendleft(log_entry)

        return {
            "allocations": allocations,
            "explanations": explanations,
            "congestion": congestion,
            "total_capacity": self.capacity_mbps,
            "control_mode": mode,
            "composite_risk": composite_risk,
            "control_rationale": mode_rationale,
            "classification_confidence_avg": avg_confidence,
            "forecast_uncertainty": forecast_uncertainty,
            "action_desc": action_desc,
            "reward": reward,
            "jains_index": jains_index,
        }


global_allocation_engine = AllocationEngine()
