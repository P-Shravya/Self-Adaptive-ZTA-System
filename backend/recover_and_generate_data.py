"""
ZenAI ZTA - Data Recovery & Synthetic Data Generator
Rebuilds devices table from behavior logs and generates training data
"""

import sqlite3
import random
from datetime import datetime, timedelta
import hashlib

DB_PATH = "zta_research.db"

# Real data from your behavior logs
REAL_USERS = [
    {"id": 1, "username": "string", "email": "string@test.com"},
    {"id": 2, "username": "ponugoti", "email": "ponugoti@test.com"},
    {"id": 3, "username": "string", "email": "string2@test.com"},
    {"id": 4, "username": "Shravya Pottumuthula", "email": "shravya@test.com"},
    {"id": 5, "username": "Manideep", "email": "manideep@test.com"},
    {"id": 6, "username": "Amulyarao", "email": "amulya@test.com"},
    {"id": 7, "username": "Laya_30", "email": "laya@test.com"},
    {"id": 8, "username": "Kavya", "email": "kavya@test.com"},
    {"id": 9, "username": "Vaishnavi_malireddy", "email": "vaishnavi@test.com"},
    {"id": 10, "username": "Krithika_reddii", "email": "krithika@test.com"},
    {"id": 11, "username": "Akhila Bhukya", "email": "akhila@test.com"},
    {"id": 12, "username": "M.SINDHUJA", "email": "sindhuja@test.com"},
]

REAL_DEVICES = [
    {"user_id": 1, "browser": "string", "os": "string", "device_type": "Desktop", "fingerprint": "string123"},
    {"user_id": 2, "browser": "Chrome", "os": "Windows", "device_type": "Desktop", "fingerprint": "247d95f2"},
    {"user_id": 3, "browser": "string", "os": "string", "device_type": "Desktop", "fingerprint": "string456"},
    {"user_id": 4, "browser": "Edge", "os": "Windows", "device_type": "Desktop", "fingerprint": "608a354e"},
    {"user_id": 5, "browser": "Chrome", "os": "Linux", "device_type": "Mobile", "fingerprint": "2119e729"},
    {"user_id": 6, "browser": "Chrome", "os": "Linux", "device_type": "Mobile", "fingerprint": "0dac1b5e"},
    {"user_id": 7, "browser": "Safari", "os": "macOS", "device_type": "Desktop", "fingerprint": "b0f1fa36"},
    {"user_id": 8, "browser": "Chrome", "os": "Windows", "device_type": "Desktop", "fingerprint": "a1ea0712"},
    {"user_id": 9, "browser": "Chrome", "os": "Linux", "device_type": "Mobile", "fingerprint": "56d5c85e"},
    {"user_id": 10, "browser": "Chrome", "os": "Linux", "device_type": "Mobile", "fingerprint": "b1de3139"},
    {"user_id": 11, "browser": "Firefox", "os": "Linux", "device_type": "Mobile", "fingerprint": "9dce89e7"},
    {"user_id": 12, "browser": "Chrome", "os": "Linux", "device_type": "Mobile", "fingerprint": "281e6e9b"},
]

BROWSERS = ["Chrome", "Firefox", "Safari", "Edge", "Opera"]
OS_OPTIONS = ["Windows", "macOS", "Linux", "Android", "iOS"]
DEVICE_TYPES = ["Desktop", "Mobile", "Tablet"]
ACTIONS = ["LOGIN", "LOGOUT", "PAGE_VIEW", "FILE_DOWNLOAD", "FILE_UPLOAD", "SETTINGS_CHANGE", "API_CALL"]
RESOURCES = ["/dashboard", "/profile", "/settings", "/api/data", "/files", "/reports", "/admin", "/logout"]
CITIES = ["Hyderabad", "Mumbai", "Delhi", "Bangalore", "Chennai", "Kolkata", "Pune", "Ahmedabad"]
COUNTRIES = ["India"]

def generate_fingerprint():
    """Generate random device fingerprint"""
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:8]

def generate_ip():
    """Generate random IP address"""
    if random.random() < 0.7:  # 70% IPv4
        return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.0"
    else:  # 30% IPv6
        parts = [f"{random.randint(0,65535):04x}" for _ in range(8)]
        return ":".join(parts)

def compute_trust_score(browser, os, hour, vpn, device_type):
    """Calculate trust score"""
    score = 0.5
    if browser in ["Chrome", "Firefox", "Safari", "Edge"]:
        score += 0.15
    if 7 <= hour <= 23:
        score += 0.15
    if vpn:
        score -= 0.20
    if os in ["Windows", "macOS", "Linux"]:
        score += 0.10
    if device_type == "Desktop":
        score += 0.05
    return round(min(1.0, max(0.0, score)), 3)

def rebuild_devices_table(conn):
    """Rebuild devices table from real data"""
    print("🔧 Rebuilding devices table...")
    cursor = conn.cursor()
    
    now = datetime.utcnow().isoformat()
    
    for device in REAL_DEVICES:
        trust = compute_trust_score(
            device["browser"], 
            device["os"], 
            random.randint(8, 18),
            0,
            device["device_type"]
        )
        
        cursor.execute("""
            INSERT OR REPLACE INTO devices 
            (user_id, device_fingerprint, device_type, os, browser, trust_score, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            device["user_id"],
            device["fingerprint"],
            device["device_type"],
            device["os"],
            device["browser"],
            trust,
            now
        ))
    
    conn.commit()
    print(f"✅ Inserted {len(REAL_DEVICES)} real devices")

def generate_synthetic_behavior_logs(conn, num_rows=400):
    """Generate synthetic behavior logs for ZTA training"""
    print(f"\n🤖 Generating {num_rows} synthetic behavior logs...")
    cursor = conn.cursor()
    
    base_date = datetime.now() - timedelta(days=30)
    
    for i in range(num_rows):
        # Pick random user
        user = random.choice(REAL_USERS)
        device = next(d for d in REAL_DEVICES if d["user_id"] == user["id"])
        
        # Random timestamp within last 30 days
        random_seconds = random.randint(0, 30 * 24 * 60 * 60)
        timestamp = base_date + timedelta(seconds=random_seconds)
        hour = timestamp.hour
        dow = timestamp.weekday()
        
        # Generate event
        ip = generate_ip()
        ip_prefix = ".".join(ip.split(".")[:3]) + ".0" if "." in ip else ip
        
        city = random.choice(CITIES)
        country = random.choice(COUNTRIES)
        
        action = random.choice(ACTIONS)
        resource = random.choice(RESOURCES)
        
        session_id = generate_fingerprint()
        session_duration = random.randint(30, 3600)  # 30 sec to 1 hour
        
        # VPN/Proxy detection (10% chance)
        vpn = 1 if random.random() < 0.1 else 0
        proxy = 1 if random.random() < 0.05 else 0
        
        cursor.execute("""
            INSERT INTO behavior_logs
            (user_id, username, timestamp, hour, day_of_week, ip_address, ip_prefix,
             location_country, location_city, device_fingerprint, device_type, os, browser,
             resource, action, session_id, session_duration, vpn_detected, proxy_detected)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            user["id"],
            user["username"],
            timestamp.isoformat(),
            hour,
            dow,
            ip,
            ip_prefix,
            country,
            city,
            device["fingerprint"],
            device["device_type"],
            device["os"],
            device["browser"],
            resource,
            action,
            session_id,
            session_duration,
            vpn,
            proxy
        ))
        
        if (i + 1) % 100 == 0:
            print(f"  Generated {i + 1}/{num_rows} rows...")
    
    conn.commit()
    print(f"✅ Generated {num_rows} synthetic behavior logs")

def update_baselines(conn):
    """Update user baselines based on behavior data"""
    print("\n🧠 Updating user baselines...")
    cursor = conn.cursor()
    
    for user in REAL_USERS:
        # Get user's behavior data
        cursor.execute("""
            SELECT hour, browser, os, ip_prefix, location_country
            FROM behavior_logs
            WHERE user_id = ?
        """, (user["id"],))
        
        rows = cursor.fetchall()
        if not rows:
            continue
        
        hours = [r[0] for r in rows]
        browsers = list(set([r[1] for r in rows]))
        os_list = list(set([r[2] for r in rows]))
        ips = list(set([r[3] for r in rows]))
        countries = list(set([r[4] for r in rows]))
        
        baseline = {
            "typical_hours": hours[:10],  # Sample
            "typical_browsers": browsers,
            "typical_os": os_list,
            "typical_ip_prefixes": ips[:5],
            "typical_countries": countries
        }
        
        import json
        cursor.execute("""
            INSERT OR REPLACE INTO user_baselines
            (user_id, baseline_data, last_updated, data_points_count, source_log_ids)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user["id"],
            json.dumps(baseline),
            datetime.utcnow().isoformat(),
            len(rows),
            json.dumps([])
        ))
    
    conn.commit()
    print(f"✅ Updated baselines for {len(REAL_USERS)} users")

def show_stats(conn):
    """Show database statistics"""
    print("\n" + "="*60)
    print("📊 DATABASE STATISTICS")
    print("="*60)
    
    cursor = conn.cursor()
    
    tables = ['users', 'devices', 'behavior_logs', 'user_baselines']
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"  {table:20s} : {count:5d} rows")
    
    print("="*60)

def main():
    """Main execution"""
    print("🚀 ZenAI ZTA - Data Recovery & Synthetic Data Generation")
    print("="*60)
    
    if not os.path.exists(DB_PATH):
        print(f"❌ Database not found: {DB_PATH}")
        return
    
    conn = sqlite3.connect(DB_PATH)
    
    try:
        # Rebuild devices table
        rebuild_devices_table(conn)
        
        # Generate synthetic data
        generate_synthetic_behavior_logs(conn, num_rows=400)
        
        # Update baselines
        update_baselines(conn)
        
        # Show final stats
        show_stats(conn)
        
        print("\n✅ DATA RECOVERY & GENERATION COMPLETE!")
        print("\nYou now have:")
        print("  • 12 real users (from your friends)")
        print("  • 12 devices with trust scores")
        print("  • 400+ behavior logs for ZTA training")
        print("  • Updated behavioral baselines")
        print("\n🎓 Ready for ZTA model training!")
        
    finally:
        conn.close()

if __name__ == "__main__":
    import os
    main()
