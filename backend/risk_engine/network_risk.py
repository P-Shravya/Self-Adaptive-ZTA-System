# backend/risk_engine/network_risk.py

import math

def calculate_network_risk(meta, baseline):

    score = 0

    # 📊 Data Transfer Spike
    avg = baseline.get("avg_data_transfer", 1)
    current = meta.get("data_transfer", 0)

    if avg > 0:
        ratio = current / avg

        if ratio > 10:
            score += 85
        elif ratio > 5:
            score += 60
        elif ratio > 2:
            score += 30

    # 🌐 Unauthorized VPN
    if meta.get("unauthorized_vpn"):
        score += 20

    # 🔍 Port Scanning
    if meta.get("port_scanning"):
        score += 90

    return min(score, 30)
