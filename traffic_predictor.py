"""
NetPilot AI — Traffic Prediction Module
=======================================
Practical short-term traffic demand forecasting using time-series analysis:
1. Baseline: Simple Moving Average (SMA)
2. Exponential Moving Average (EMA) with linear trend projection (Holt's method)
3. Evaluates forecast accuracy using Mean Absolute Error (MAE) and RMSE.
4. Distinguishes observed actuals from future predictions.
"""

import os
import csv
import time
import math
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from config import TRAFFIC_CSV


class TrafficPredictor:
    """
    Computes practical short-term forecasts of network throughput demand using:
    1. Baseline: Simple Moving Average (SMA)
    2. Holt-Winters Triple Exponential Smoothing (Level, Trend, and Seasonality)
    3. Peak-Hour Historical Demand Pattern Analysis & Congestion Risk Forecasting
    4. Evaluates forecast accuracy using Mean Absolute Error (MAE) and in-sample residuals.
    """

    def __init__(self, csv_path: str = TRAFFIC_CSV):
        self.csv_path = csv_path
        self._cached_peak_analysis: Optional[Dict[str, Any]] = None
        self._last_peak_calc_time = 0.0

    def load_historical_series(self, max_samples: int = 150) -> List[Dict[str, Any]]:
        """Load recent aggregated traffic series from CSV."""
        if not os.path.exists(self.csv_path):
            return []

        rows = []
        try:
            with open(self.csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        down = float(row.get("Download Mbps", 0.0) or 0.0)
                        up = float(row.get("Upload Mbps", 0.0) or 0.0)
                        ts = row.get("Timestamp", "")
                        rows.append({"timestamp": ts, "down_mbps": down, "up_mbps": up})
                    except (ValueError, TypeError):
                        continue
        except Exception:
            return []

        return rows[-max_samples:]

    def _simple_moving_average(self, series: List[float], window: int = 4) -> List[float]:
        """Compute simple moving average."""
        if len(series) < window:
            return series[:]
        result = []
        for i in range(len(series)):
            start_idx = max(0, i - window + 1)
            window_slice = series[start_idx : i + 1]
            result.append(sum(window_slice) / len(window_slice))
        return result

    def _holt_winters_triple_smoothing(
        self,
        series: List[float],
        alpha: float = 0.35,
        beta: float = 0.20,
        gamma: float = 0.15,
        season_length: int = 4,
        horizon: int = 6,
    ) -> Tuple[List[float], List[float]]:
        """
        Holt-Winters Triple Exponential Smoothing with Additive Seasonality:
        - Level:   L_t = alpha * (Y_t - S_{t-m}) + (1 - alpha) * (L_{t-1} + b_{t-1})
        - Trend:   b_t = beta * (L_t - L_{t-1}) + (1 - beta) * b_{t-1}
        - Season:  S_t = gamma * (Y_t - L_t) + (1 - gamma) * S_{t-m}
        - Forecast: F_{t+h} = L_t + h * b_t + S_{t+h-m}
        """
        n = len(series)
        if n == 0:
            return [], []
        if n < season_length * 2:
            # Fall back to Holt's linear trend when sample length is smaller than 2 seasons
            return self._exponential_smoothing_trend(series, alpha=alpha, beta=beta, horizon=horizon)

        # Initial level and trend from the first two seasons
        level = sum(series[:season_length]) / season_length
        next_level = sum(series[season_length : season_length * 2]) / season_length
        trend = (next_level - level) / season_length

        # Initial seasonal indices (additive)
        seasonals = [series[i] - level for i in range(season_length)]

        fitted = []
        for i in range(n):
            val = series[i]
            s_idx = i % season_length
            prev_level = level
            prev_trend = trend
            prev_season = seasonals[s_idx]

            # Update level, trend, and seasonality
            level = alpha * (val - prev_season) + (1.0 - alpha) * (prev_level + prev_trend)
            trend = beta * (level - prev_level) + (1.0 - beta) * prev_trend
            seasonals[s_idx] = gamma * (val - level) + (1.0 - gamma) * prev_season

            pred_in_sample = max(0.0, prev_level + prev_trend + prev_season)
            fitted.append(round(pred_in_sample, 2))

        # Generate out-of-sample forecast horizon
        forecast = []
        for h in range(1, horizon + 1):
            s_idx = (n + h - 1) % season_length
            projected = max(0.0, level + (h * trend) + seasonals[s_idx])
            forecast.append(round(projected, 2))

        return fitted, forecast

    def _exponential_smoothing_trend(
        self, series: List[float], alpha: float = 0.35, beta: float = 0.20, horizon: int = 6
    ) -> Tuple[List[float], List[float]]:
        """
        Holt's linear exponential smoothing with level and trend.
        Returns (fitted_in_sample, forecast_horizon).
        """
        if not series:
            return [], []

        level = series[0]
        trend = (series[1] - series[0]) if len(series) > 1 else 0.0
        fitted = [level]

        for i in range(1, len(series)):
            val = series[i]
            prev_level = level
            level = alpha * val + (1.0 - alpha) * (level + trend)
            trend = beta * (level - prev_level) + (1.0 - beta) * trend
            fitted.append(max(0.0, level + trend))

        forecast = []
        for h in range(1, horizon + 1):
            projected = max(0.0, level + (h * trend))
            forecast.append(round(projected, 2))

        return fitted, forecast

    def analyze_peak_hours(self) -> Dict[str, Any]:
        """
        Analyze diurnal usage patterns from the historical traffic CSV dataset.
        Identifies peak usage hours, calculates surge multiplier, and forecasts congestion risk.
        """
        now = datetime.now()
        current_hour = now.hour

        # Cache peak analysis for 60 seconds to avoid repetitive file I/O
        if self._cached_peak_analysis and (time.time() - self._last_peak_calc_time < 60.0):
            res = dict(self._cached_peak_analysis)
            res["current_hour"] = current_hour
            res["is_peak_hour"] = current_hour in res.get("peak_hours", [])
            return res

        hourly_totals: Dict[int, List[float]] = {}
        if os.path.exists(self.csv_path):
            try:
                with open(self.csv_path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for r in reader:
                        ts = r.get("Timestamp", "")
                        try:
                            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                            h = dt.hour
                            mbps = float(r.get("Download Mbps", 0.0) or 0.0)
                            if h not in hourly_totals:
                                hourly_totals[h] = []
                            hourly_totals[h].append(mbps)
                        except Exception:
                            continue
            except Exception:
                pass

        # Compute hourly averages
        hourly_avgs = {}
        for h, vals in hourly_totals.items():
            if vals:
                hourly_avgs[h] = round(sum(vals) / len(vals), 4)

        if hourly_avgs:
            overall_avg = max(0.001, sum(hourly_avgs.values()) / len(hourly_avgs))
            sorted_hours = sorted(hourly_avgs.items(), key=lambda x: x[1], reverse=True)
            # Top 30% of highest volume hours are identified as peak hours
            cutoff_count = max(1, len(sorted_hours) // 3)
            peak_hours = sorted([h for h, _ in sorted_hours[:cutoff_count]])

            current_avg = hourly_avgs.get(current_hour, overall_avg)
            surge_multiplier = round(max(1.0, current_avg / overall_avg), 2)
        else:
            # Default sensible diurnal pattern: peak hours 18:00 - 23:00 (evening)
            peak_hours = [18, 19, 20, 21, 22]
            hourly_avgs = {h: 0.05 if h in peak_hours else 0.01 for h in range(24)}
            surge_multiplier = 1.6 if current_hour in peak_hours else 1.0

        is_peak = current_hour in peak_hours
        if is_peak:
            status = "PEAK_HOUR"
            status_desc = f"Peak-Hour Window Active ({current_hour:02d}:00). Expect elevated demand surge."
            risk_score = min(95.0, 50.0 + (surge_multiplier * 15.0))
        elif any(abs(current_hour - ph) == 1 for ph in peak_hours):
            status = "SHOULDER"
            status_desc = f"Approaching Peak-Hour Window. Demand trend ramping up."
            risk_score = 45.0
        else:
            status = "OFF_PEAK"
            status_desc = "Normal Off-Peak Baseline. Standard priority scheduling in effect."
            risk_score = 15.0

        result = {
            "current_hour": current_hour,
            "is_peak_hour": is_peak,
            "status": status,
            "status_description": status_desc,
            "peak_hours": peak_hours,
            "peak_hours_formatted": ", ".join(f"{h:02d}:00" for h in peak_hours),
            "surge_multiplier": surge_multiplier,
            "congestion_risk_pct": round(risk_score, 1),
            "historical_hourly_avg_mbps": hourly_avgs,
        }
        self._cached_peak_analysis = result
        self._last_peak_calc_time = time.time()
        return result

    def calculate_mae(self, actual: List[float], predicted: List[float]) -> float:
        """Calculate Mean Absolute Error between actual and predicted vectors."""
        if not actual or not predicted:
            return 0.0
        n = min(len(actual), len(predicted))
        if n == 0:
            return 0.0
        abs_err = sum(abs(actual[i] - predicted[i]) for i in range(n))
        return round(abs_err / n, 3)

    def calculate_rmse(self, actual: List[float], predicted: List[float]) -> float:
        """Calculate Root Mean Square Error between actual and predicted vectors."""
        if not actual or not predicted:
            return 0.0
        n = min(len(actual), len(predicted))
        if n == 0:
            return 0.0
        sq_err = sum((actual[i] - predicted[i]) ** 2 for i in range(n))
        return round(math.sqrt(sq_err / n), 3)

    def compute_uncertainty_envelope(
        self,
        actual: List[float],
        fitted: List[float],
        forecast: List[float],
        confidence_level: float = 0.95,
    ) -> Dict[str, Any]:
        """
        Quantifies prediction uncertainty envelope and residual variance.
        Constructs dynamic upper and lower demand intervals [D̂ - kσ, D̂ + kσ].
        Detects sudden volatility drifts in incoming traffic.
        """
        if not actual or not fitted or not forecast:
            return {
                "upper_bounds": list(forecast or []),
                "lower_bounds": list(forecast or []),
                "forecast_uncertainty": 0.20,
                "residual_std": 0.0,
                "drift_detected": False,
                "volatility_risk": "low",
                "envelope": [],
            }

        n = min(len(actual) - 1, len(fitted) - 1)
        if n <= 1:
            return {
                "upper_bounds": list(forecast),
                "lower_bounds": [max(0.0, x * 0.8) for x in forecast],
                "forecast_uncertainty": 0.20,
                "residual_std": 0.5,
                "drift_detected": False,
                "volatility_risk": "low",
                "envelope": [],
            }

        residuals = [actual[i + 1] - fitted[i] for i in range(n)]
        var = sum(r * r for r in residuals) / max(1, n)
        sigma = math.sqrt(max(0.001, var))

        # Standard normal critical value: 1.96 for 95% interval
        z = 1.96 if confidence_level >= 0.95 else 1.645

        upper_bounds = []
        lower_bounds = []
        envelope = []
        for h, val in enumerate(forecast, start=1):
            # Variance expands with forecasting horizon: σ_h = σ * sqrt(1 + (h-1)*0.22)
            sigma_h = sigma * math.sqrt(1.0 + (h - 1) * 0.22)
            margin = z * sigma_h
            u_bound = round(max(0.0, val + margin), 2)
            l_bound = round(max(0.0, val - margin), 2)
            upper_bounds.append(u_bound)
            lower_bounds.append(l_bound)
            envelope.append({
                "horizon_step": h,
                "predicted_mbps": round(val, 2),
                "lower_bound_mbps": l_bound,
                "upper_bound_mbps": u_bound,
                "confidence_margin": round(margin, 2),
            })

        # Relative forecast uncertainty score U_forecast in [0.05, 1.0]
        base_demand = max(1.0, forecast[0] if forecast else 1.0)
        u_ratio = round(min(1.0, max(0.05, (1.96 * sigma) / base_demand)), 3)

        # Detect sudden drift: last residual exceeds 2.5 * sigma
        recent_err = abs(residuals[-1]) if residuals else 0.0
        drift_detected = bool(recent_err > (2.5 * sigma) and recent_err > 1.5)

        volatility_risk = "high" if u_ratio > 0.60 or drift_detected else ("medium" if u_ratio > 0.35 else "low")

        return {
            "upper_bounds": upper_bounds,
            "lower_bounds": lower_bounds,
            "forecast_uncertainty": u_ratio,
            "residual_std": round(sigma, 3),
            "drift_detected": drift_detected,
            "volatility_risk": volatility_risk,
            "envelope": envelope,
        }

    def forecast(
        self, memory_history: Optional[List[Dict[str, Any]]] = None, horizon: int = 6
    ) -> Dict[str, Any]:
        """
        Generate short-term traffic predictions with uncertainty envelopes.
        Uses in-memory history if provided; falls back to CSV if None.
        """
        if memory_history is not None:
            raw_series = [float(p.get("down", 0.0)) for p in memory_history if "down" in p]
        else:
            csv_data = self.load_historical_series(max_samples=60)
            raw_series = [p["down_mbps"] for p in csv_data]

        if len(raw_series) < 3:
            return {
                "status": "insufficient_data",
                "message": "Collecting more traffic samples for statistical forecast (< 3 points).",
                "observed": raw_series,
                "forecast": [],
                "forecast_upper": [],
                "forecast_lower": [],
                "forecast_uncertainty": 0.20,
                "mae": 0.0,
                "rmse": 0.0,
                "model": "Holt-Winters Linear Trend",
            }

        # Keep last 25 observed points for clean presentation
        recent_observed = [round(x, 2) for x in raw_series[-25:]]

        # Calculate SMA baseline
        sma_fitted = self._simple_moving_average(recent_observed, window=4)

        # Calculate Holt-Winters triple exponential smoothing forecast
        fitted, future_forecast = self._holt_winters_triple_smoothing(
            recent_observed, alpha=0.35, beta=0.20, gamma=0.15, season_length=4, horizon=horizon
        )

        # Evaluate MAE and RMSE on in-sample fitted vs actual
        mae = self.calculate_mae(recent_observed[1:], fitted[:-1])
        rmse = self.calculate_rmse(recent_observed[1:], fitted[:-1])

        # Evaluate dynamic uncertainty envelope & residual variance
        unc_data = self.compute_uncertainty_envelope(recent_observed, fitted, future_forecast)

        # Evaluate diurnal peak-hour traffic patterns from historical database
        peak_info = self.analyze_peak_hours()

        return {
            "status": "ready",
            "observed": recent_observed,
            "fitted_baseline": [round(x, 2) for x in sma_fitted],
            "forecast": future_forecast,
            "forecast_upper": unc_data["upper_bounds"],
            "forecast_lower": unc_data["lower_bounds"],
            "forecast_uncertainty": unc_data["forecast_uncertainty"],
            "uncertainty_envelope": unc_data["envelope"],
            "drift_detected": unc_data["drift_detected"],
            "volatility_risk": unc_data["volatility_risk"],
            "residual_std": unc_data["residual_std"],
            "horizon_steps": horizon,
            "step_interval_s": 2.5,
            "mae": mae,
            "rmse": rmse,
            "model": "Holt-Winters Triple Exponential Smoothing with Dynamic Uncertainty Envelope",
            "peak_hour_analysis": peak_info,
            "peak_status": peak_info.get("status", "OFF_PEAK"),
            "is_peak_hour": peak_info.get("is_peak_hour", False),
            "surge_multiplier": peak_info.get("surge_multiplier", 1.0),
            "congestion_risk_pct": peak_info.get("congestion_risk_pct", 15.0),
            "interpretation": (
                f"MAE: {mae} Mbps, RMSE: {rmse} Mbps. Forecast Uncertainty: {unc_data['forecast_uncertainty']*100:.1f}%. "
                f"Volatility: {unc_data['volatility_risk'].upper()}. {peak_info.get('status_description', '')}"
            ),
        }


global_predictor = TrafficPredictor()
