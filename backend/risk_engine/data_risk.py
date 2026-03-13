# backend/risk_engine/data_risk.py

import math

def calculate_data_risk(meta, baseline):

    score = 0

    avg = baseline.get("avg_download_volume", 1)
    volume = meta.get("download_volume", 0)
    sensitivity = meta.get("file_sensitivity", 0)

    if avg > 0 and volume > avg:
        score += sensitivity * math.log(volume / avg + 1) * 20

    if meta.get("external_upload"):
        score += 85

    return min(score, 50)