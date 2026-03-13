# backend/risk_engine/risk_engine.py

from .identity_risk import calculate_identity_risk
from .device_risk import calculate_device_risk
from .network_risk import calculate_network_risk
from .resource_risk import calculate_resource_risk
from .behavior_risk import calculate_behavior_risk
from .data_risk import calculate_data_risk
from .risk_config import CRITICAL_OVERRIDES


class RiskEngine:

    def evaluate(self, meta, baseline):

        flags = []

        # ===============================
        # Identity Risk
        # ===============================
        identity_result = calculate_identity_risk(meta, baseline)
        identity = identity_result["risk"]
        id_flags = identity_result["flags"]
        flags += id_flags

        # ===============================
        # Device Risk
        # ===============================
        device, dev_flags = calculate_device_risk(meta, baseline)
        flags += dev_flags

        # ===============================
        # Network Risk
        # ===============================
        network = calculate_network_risk(meta, baseline)

        # ===============================
        # Resource Risk
        # ===============================
        resource, res_flags = calculate_resource_risk(meta)
        flags += res_flags

        # ===============================
        # Behavior Risk
        # ===============================
        behavior = calculate_behavior_risk(meta, baseline)

        # ===============================
        # Data Risk
        # ===============================
        data = calculate_data_risk(meta, baseline)

        # ===============================
        # Critical Override
        # ===============================
        for flag in flags:
            if flag in CRITICAL_OVERRIDES:
                return {
                    "score": 100,
                    "flags": flags
                }

        # ===============================
        # Final Risk Score
        # ===============================
        final_score = identity + device + network + resource + behavior + data
        final_score = min(final_score, 100)

        return {
            "score": round(final_score, 2),
            "flags": flags
        }
    