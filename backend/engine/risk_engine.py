"""
FAIR-CAM Risk Quantification and Vectorized Monte Carlo Simulation Engine.
Implements Open FAIR™ (Factor Analysis of Information Risk) standard:
- Loss Event Frequency (LEF) = Threat Event Frequency (TEF) x Vulnerability (Threat Cap > Resistance)
- Loss Magnitude (LM) = Primary Losses (Downtime, Response, Recovery) + Secondary Losses (RBI, SEBI, DPDP, Breach)
- 10,000 Vectorized Monte Carlo Runs generating EAL, 95% VaR, 99% VaR, CVaR, and Loss Exceedance Curves.
"""

import numpy as np
from typing import List, Dict, Optional, Tuple, Any
from backend.models.schemas import (
    Asset, CriticalityTier, QuantifiedRiskResult,
    LossExceedancePoint, BusinessUnit
)
from backend.ingestion.telemetry_loader import TelemetryService, USD_INR_RATE


class FairRiskEngine:
    """
    Monte Carlo Risk Engine computing monetary cyber exposure across enterprise assets.
    Optimized with vectorized PERT sampling and memoized baseline simulations.
    """

    def __init__(self, iterations: int = 10000, seed: int = 42):
        self.iterations = iterations
        self.seed = seed
        self.telemetry_service = TelemetryService.get_instance()
        self._cached_baseline_result: Optional[QuantifiedRiskResult] = None

    def invalidate_cache(self):
        """Invalidates memoized baseline simulations."""
        self._cached_baseline_result = None

    def _sample_pert(
        self,
        low: float,
        mode: float,
        high: float,
        size: int,
        rng: Optional[np.random.Generator] = None
    ) -> np.ndarray:
        """
        Samples from a Beta-PERT distribution with shape parameter gamma=4 using thread-safe Generator.
        """
        if high <= low:
            return np.full(size, low)
        # Ensure mode lies strictly within [low, high]
        mode = max(low, min(high, mode))
        alpha = 1.0 + 4.0 * (mode - low) / (high - low)
        beta = 1.0 + 4.0 * (high - mode) / (high - low)
        gen = rng if rng is not None else np.random.default_rng(self.seed)
        samples = gen.beta(alpha, beta, size=size)
        return low + samples * (high - low)

    def simulate_asset_loss(
        self,
        asset: Asset,
        initiative_boosts: Optional[Dict[str, float]] = None,
        custom_overrides: Optional[Dict[str, Any]] = None,
        rng: Optional[np.random.Generator] = None
    ) -> Tuple[np.ndarray, Dict[str, float], Dict[str, float]]:
        """
        Simulates annual loss for an asset across 10,000 iterations using isolated thread-safe RNG.
        Returns:
            - total_loss_vector: np.ndarray of length self.iterations
            - primary_loss_summary: dict of mean primary loss components in INR
            - secondary_loss_summary: dict of mean secondary loss components in INR
        """
        gen = rng if rng is not None else np.random.default_rng(self.seed)

        # 1. Compute Threat Event Frequency (TEF) & Capability
        base_tef, threat_cap = self.telemetry_service.compute_asset_threat_exposure(asset)

        # Apply any custom overrides (e.g. from What-If scenarios)
        if custom_overrides:
            if "tef_multiplier" in custom_overrides:
                base_tef *= custom_overrides["tef_multiplier"]
            if "threat_cap_delta" in custom_overrides:
                threat_cap = min(0.99, max(0.1, threat_cap + custom_overrides["threat_cap_delta"]))

        # Sample annual threat event occurrences via Poisson distribution
        # Each threat event represents a targeted exploit/attack campaign
        tef_events = gen.poisson(lam=max(0.2, base_tef), size=self.iterations)

        # 2. Control Resistance Strength
        resistance = self.telemetry_service.compute_asset_resistance(asset, initiative_boosts)
        if custom_overrides and "resistance_override" in custom_overrides:
            resistance = custom_overrides["resistance_override"]
        elif custom_overrides and "resistance_delta" in custom_overrides:
            resistance = min(0.98, max(0.05, resistance + custom_overrides["resistance_delta"]))

        # Vulnerability: Probability that Threat Capability overcomes Resistance Strength
        # Modeled as logistic difference function with noise
        t_cap_samples = self._sample_pert(
            max(0.1, threat_cap - 0.15),
            threat_cap,
            min(1.0, threat_cap + 0.10),
            size=self.iterations,
            rng=gen
        )
        r_str_samples = self._sample_pert(
            max(0.05, resistance - 0.12),
            resistance,
            min(0.99, resistance + 0.08),
            size=self.iterations,
            rng=gen
        )

        # Fraction of threat events that become actual compromise events (LEF)
        # If t_cap > r_str, exploit succeeds
        breach_prob = 1.0 / (1.0 + np.exp(-12.0 * (t_cap_samples - r_str_samples)))
        # Annual loss events
        loss_event_counts = gen.binomial(n=tef_events, p=np.clip(breach_prob, 0.01, 0.99))

        # Filter iterations where at least one loss event occurred
        has_incident = (loss_event_counts > 0)
        n_incidents = loss_event_counts

        # 3. Primary Loss Calculations (per incident)
        # a) Downtime Loss (Hours x Revenue / hr)
        rto = asset.rto_hours
        if custom_overrides and "rto_multiplier" in custom_overrides:
            target_assets = custom_overrides.get("target_assets")
            target_tiers = custom_overrides.get("target_asset_tiers")
            apply_rto = True
            if target_assets is not None:
                current_assets = self.telemetry_service.get_all_assets()
                current_ids = {a.asset_id for a in current_assets}
                has_direct_target = any(tid in current_ids for tid in target_assets)
                if has_direct_target:
                    apply_rto = (asset.asset_id in target_assets)
                else:
                    # Fallback for industry presets and custom imports:
                    # Target the top Tier 1 crown jewel asset (highest hourly downtime)
                    tier_1_assets = [a for a in current_assets if a.criticality == CriticalityTier.TIER_1]
                    if tier_1_assets:
                        top_t1 = max(tier_1_assets, key=lambda a: a.revenue_per_hour_inr)
                        apply_rto = (asset.asset_id == top_t1.asset_id)
                    elif current_assets:
                        apply_rto = (asset.asset_id == current_assets[0].asset_id)
                    else:
                        apply_rto = False
            elif target_tiers is not None:
                apply_rto = (asset.criticality in target_tiers or (hasattr(asset.criticality, "value") and asset.criticality.value in target_tiers))
            if apply_rto:
                rto *= custom_overrides["rto_multiplier"]

        downtime_hours = self._sample_pert(
            low=0.3 * rto,
            mode=rto,
            high=3.5 * rto,
            size=self.iterations,
            rng=gen
        )
        downtime_loss_per_event = downtime_hours * asset.revenue_per_hour_inr

        # b) Incident Response & Forensic Investigation (₹ INR)
        ir_cost_per_event = self._sample_pert(
            low=500000.0,    # ₹5 Lakhs
            mode=1500000.0,  # ₹15 Lakhs
            high=4500000.0,  # ₹45 Lakhs
            size=self.iterations,
            rng=gen
        )

        # c) Data Recovery & System Replacement (₹ INR)
        recovery_cost_per_event = self._sample_pert(
            low=300000.0,    # ₹3 Lakhs
            mode=1200000.0,  # ₹12 Lakhs
            high=3800000.0,  # ₹38 Lakhs
            size=self.iterations,
            rng=gen
        )

        total_primary_loss = (downtime_loss_per_event + ir_cost_per_event + recovery_cost_per_event) * n_incidents

        # 4. Secondary Loss Calculations
        # Secondary regulatory/legal actions only trigger during major catastrophic compromises
        # (not every technical event escalates to a public DPDP/SEBI penalty)
        if asset.criticality == CriticalityTier.TIER_1:
            sec_prob = 0.08  # 8% chance per annual cycle of major regulatory escalation
        elif asset.criticality == CriticalityTier.TIER_2:
            sec_prob = 0.03
        else:
            sec_prob = 0.008

        secondary_triggered = (gen.random(size=self.iterations) < sec_prob) & has_incident

        # a) Regulatory Penalties (RBI, SEBI CSCRF, DPDP Act 2023)
        # Severe statutory sanctions apply for significant personal data leaks regardless of tier
        if asset.pii_records_count > 1000000 or (asset.criticality == CriticalityTier.TIER_1 and asset.pii_records_count > 100000):
            reg_penalty = self._sample_pert(
                low=15000000.0,   # ₹1.5 Crore
                mode=45000000.0,  # ₹4.5 Crore
                high=120000000.0, # ₹12 Crore (major DPDP sanction)
                size=self.iterations,
                rng=gen
            )
        elif asset.criticality == CriticalityTier.TIER_1:
            reg_penalty = self._sample_pert(
                low=4000000.0,    # ₹40 Lakhs (RBI/SEBI regulatory penalty)
                mode=12000000.0,  # ₹1.2 Crore
                high=30000000.0,  # ₹3.0 Crore
                size=self.iterations,
                rng=gen
            )
        else:
            reg_penalty = self._sample_pert(
                low=500000.0,
                mode=1500000.0,
                high=5000000.0,
                size=self.iterations,
                rng=gen
            )

        # b) Customer Data Breach Notification & Legal Redressal (₹ INR per record)
        # Cost per compromised record sampled between ₹250 and ₹750
        if asset.pii_records_count > 0:
            # During a major breach, typical breach sample is 0.5% to 4% of total repository
            breached_fraction = self._sample_pert(low=0.002, mode=0.015, high=0.06, size=self.iterations, rng=gen)
            breached_records = asset.pii_records_count * breached_fraction
            cost_per_record = self._sample_pert(low=180.0, mode=350.0, high=650.0, size=self.iterations, rng=gen)
            breach_liability = breached_records * cost_per_record
        else:
            breach_liability = np.zeros(self.iterations)

        # c) Reputational & Customer Churn Damage
        reputational_loss = (downtime_loss_per_event * 0.45) * n_incidents

        total_secondary_loss = np.where(
            secondary_triggered,
            reg_penalty + breach_liability + reputational_loss,
            0.0
        )

        total_loss = total_primary_loss + total_secondary_loss

        primary_summary = {
            "downtime_inr": float(np.mean(downtime_loss_per_event * n_incidents)),
            "incident_response_inr": float(np.mean(ir_cost_per_event * n_incidents)),
            "system_recovery_inr": float(np.mean(recovery_cost_per_event * n_incidents)),
        }
        secondary_summary = {
            "regulatory_penalties_inr": float(np.mean(np.where(secondary_triggered, reg_penalty, 0.0))),
            "breach_liability_inr": float(np.mean(np.where(secondary_triggered, breach_liability, 0.0))),
            "reputational_churn_inr": float(np.mean(np.where(secondary_triggered, reputational_loss, 0.0))),
        }

        return total_loss, primary_summary, secondary_summary

    def run_enterprise_simulation(
        self,
        initiative_boosts: Optional[Dict[str, float]] = None,
        custom_overrides: Optional[Dict[str, Any]] = None
    ) -> QuantifiedRiskResult:
        """
        Runs the full 10,000-iteration Monte Carlo simulation across all enterprise assets.
        Aggregates EAL, 95% VaR, 99% VaR, CVaR, Loss Exceedance Curve, and BU breakdowns.
        Uses isolated, thread-safe Generator to guarantee determinism without global state mutation.
        Returns sub-millisecond memoized result for unparameterized baseline queries.
        """
        is_baseline = (not initiative_boosts) and (not custom_overrides)
        if is_baseline and self._cached_baseline_result is not None:
            return self._cached_baseline_result

        rng = np.random.default_rng(self.seed)
        assets = self.telemetry_service.get_all_assets()

        enterprise_loss_matrix = np.zeros(self.iterations)
        asset_eals: Dict[str, float] = {}
        bu_loss_inr: Dict[str, float] = {bu.value: 0.0 for bu in BusinessUnit}
        tier_loss_inr: Dict[str, float] = {tier.value: 0.0 for tier in CriticalityTier}

        total_primary: Dict[str, float] = {
            "downtime_inr": 0.0, "incident_response_inr": 0.0, "system_recovery_inr": 0.0
        }
        total_secondary: Dict[str, float] = {
            "regulatory_penalties_inr": 0.0, "breach_liability_inr": 0.0, "reputational_churn_inr": 0.0
        }

        top_assets_tracker = []

        for asset in assets:
            loss_vec, prim, sec = self.simulate_asset_loss(asset, initiative_boosts, custom_overrides, rng=rng)
            enterprise_loss_matrix += loss_vec

            asset_eal = float(np.mean(loss_vec))
            asset_eals[asset.asset_id] = asset_eal

            # BU and Tier aggregation
            bu_key = asset.business_unit.value if hasattr(asset.business_unit, "value") else str(asset.business_unit)
            tier_key = asset.criticality.value if hasattr(asset.criticality, "value") else str(asset.criticality)
            bu_loss_inr[bu_key] = bu_loss_inr.get(bu_key, 0.0) + asset_eal
            tier_loss_inr[tier_key] = tier_loss_inr.get(tier_key, 0.0) + asset_eal

            for k in total_primary:
                total_primary[k] += prim[k]
            for k in total_secondary:
                total_secondary[k] += sec[k]

            top_vuln = max(asset.vulnerabilities, key=lambda v: (1 if v.is_cisa_kev else 0, v.epss_score, v.cvss_score)) if asset.vulnerabilities else None
            top_assets_tracker.append({
                "asset_id": asset.asset_id,
                "asset_name": asset.name,
                "business_unit": bu_key,
                "criticality": tier_key,
                "eal_inr": round(asset_eal, 2),
                "eal_usd": round(asset_eal / USD_INR_RATE, 2),
                "open_cves_count": len(asset.vulnerabilities),
                "top_cve": top_vuln.cve_id if top_vuln else "None",
                "max_epss": top_vuln.epss_score if top_vuln else 0.0
            })

        # Sort top assets by EAL descending
        top_assets_tracker.sort(key=lambda x: x["eal_inr"], reverse=True)

        # Enterprise aggregate statistics
        mean_eal_inr = float(np.mean(enterprise_loss_matrix))
        var_90_inr = float(np.percentile(enterprise_loss_matrix, 90))
        var_95_inr = float(np.percentile(enterprise_loss_matrix, 95))
        var_99_inr = float(np.percentile(enterprise_loss_matrix, 99))

        # CVaR (Expected Shortfall): Mean of losses exceeding VaR 95
        tail_losses = enterprise_loss_matrix[enterprise_loss_matrix >= var_95_inr]
        cvar_95_inr = float(np.mean(tail_losses)) if len(tail_losses) > 0 else var_95_inr

        # Loss Exceedance Curve (P(Loss >= x))
        # Percentiles corresponding to exceedance probabilities
        exceedance_pcts = [0.01, 0.05, 0.10, 0.20, 0.30, 0.50, 0.75, 0.90]
        lec_points: List[LossExceedancePoint] = []
        for p in exceedance_pcts:
            # 1 - p percentile
            amt_inr = float(np.percentile(enterprise_loss_matrix, (1.0 - p) * 100))
            lec_points.append(
                LossExceedancePoint(
                    loss_amount_inr=round(amt_inr, 2),
                    loss_amount_usd=round(amt_inr / USD_INR_RATE, 2),
                    exceedance_probability=p
                )
            )

        # Enterprise Risk Score: 0 (safe) to 100 (critical risk)
        # Scaled smoothly using exponential saturation relative to enterprise risk tolerance (₹50 Cr benchmark)
        # Low (<35), Medium (35-65), High (65-85), Critical (>85)
        risk_score = min(99.0, max(5.0, 100.0 * (1.0 - np.exp(-mean_eal_inr / 550000000.0))))

        # Determine dynamic data-driven recommended VaR confidence level:
        # Critical banking, energy, defense, or high tail exposure mandates 99% VaR (Basel III / RBI CSCRF)
        meta = self.telemetry_service.get_active_metadata()
        sector_str = str(meta.get("sector", "")).lower()
        name_str = str(meta.get("name", "")).lower()

        is_critical_sector = any(kw in sector_str or kw in name_str for kw in [
            "bank", "financ", "trad", "insur", "defense", "critical infrastructure", "energy", "aviation", "aerospace", "pharma"
        ])
        is_retail_or_operational = any(kw in sector_str or kw in name_str for kw in [
            "retail", "consumer", "media", "entertainment", "hospitality", "travel", "telecom"
        ])

        if is_critical_sector or risk_score >= 82.0:
            recommended_var_percentile = 99
            sector_name = meta.get("name") or meta.get("sector") or "Banking & Critical Infrastructure"
            recommended_var_reason = f"Mandated 99% Tail VaR (1-in-100 Yr) for {sector_name} (Basel III & RBI CSCRF)"
        elif is_retail_or_operational and risk_score < 75.0:
            recommended_var_percentile = 90
            sector_name = meta.get("name") or meta.get("sector") or "Retail & Consumer"
            recommended_var_reason = f"Operational 90% VaR (1-in-10 Yr) for {sector_name} Agile Operations"
        else:
            recommended_var_percentile = 95
            sector_name = meta.get("name") or meta.get("sector") or "Enterprise Standard"
            recommended_var_reason = f"Standard 95% Enterprise VaR (1-in-20 Yr) for {sector_name}"

        # Converted USD maps
        bu_loss_usd = {k: round(v / USD_INR_RATE, 2) for k, v in bu_loss_inr.items()}
        tier_loss_usd = {k: round(v / USD_INR_RATE, 2) for k, v in tier_loss_inr.items()}

        result = QuantifiedRiskResult(
            currency_base="INR",
            expected_annual_loss_inr=round(mean_eal_inr, 2),
            expected_annual_loss_usd=round(mean_eal_inr / USD_INR_RATE, 2),
            var_90_inr=round(var_90_inr, 2),
            var_90_usd=round(var_90_inr / USD_INR_RATE, 2),
            var_95_inr=round(var_95_inr, 2),
            var_95_usd=round(var_95_inr / USD_INR_RATE, 2),
            var_99_inr=round(var_99_inr, 2),
            var_99_usd=round(var_99_inr / USD_INR_RATE, 2),
            cvar_95_inr=round(cvar_95_inr, 2),
            cvar_95_usd=round(cvar_95_inr / USD_INR_RATE, 2),
            recommended_var_percentile=recommended_var_percentile,
            recommended_var_reason=recommended_var_reason,
            enterprise_risk_score=round(risk_score, 1),
            loss_exceedance_curve=lec_points,
            loss_by_bu_inr={k: round(v, 2) for k, v in bu_loss_inr.items()},
            loss_by_bu_usd=bu_loss_usd,
            loss_by_tier_inr={k: round(v, 2) for k, v in tier_loss_inr.items()},
            loss_by_tier_usd=tier_loss_usd,
            top_risk_assets=top_assets_tracker[:5],
            primary_loss_breakdown_inr={k: round(v, 2) for k, v in total_primary.items()},
            secondary_loss_breakdown_inr={k: round(v, 2) for k, v in total_secondary.items()},
            total_simulations=self.iterations
        )

        if is_baseline:
            self._cached_baseline_result = result

        return result
