# backend/risk_engine/device_risk.py

def calculate_device_risk(meta, baseline):

    score = 0
    flags = []

    # 🔴 Rooted Device
    if meta.get("rooted_device"):
        flags.append("rooted_device")
        return 100, flags

    # 🖥 New Device
    if meta["device_id"] not in baseline["known_devices"]:
        score += 25

    # 🛡 Device Posture
    if meta.get("antivirus_off"):
        score += 20

    if meta.get("firewall_off"):
        score += 15

    if meta.get("os_outdated"):
        score += 10

    return min(score, 30), flags