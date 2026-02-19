"""
ZTA Data Generator - Matches User's Exact Schema
Creates users.db with 3 tables: users, behavior_logs, user_baselines
"""

import sqlite3
import hashlib
import random
import json
from datetime import datetime, timedelta

DATABASE_NAME = "users.db"

# Sample data pools
ROLES = ["admin", "user", "manager", "developer", "analyst", "support"]
BROWSERS = ["Chrome", "Firefox", "Safari", "Edge", "Opera"]
OS_OPTIONS = ["Windows", "macOS", "Linux", "Android", "iOS"]
DEVICE_TYPES = ["Desktop", "Mobile", "Tablet"]
ACTIONS = ["LOGIN", "LOGOUT", "VIEW", "EDIT", "DELETE", "DOWNLOAD", "UPLOAD", "CREATE"]
RESOURCES = ["/dashboard", "/profile", "/settings", "/files", "/reports", "/api/data", "/admin", "/analytics"]
CITIES = ["Hyderabad", "Mumbai", "Delhi", "Bangalore", "Chennai", "Kolkata", "Pune", "Ahmedabad", "Jaipur", "Lucknow"]
COUNTRIES = ["India"]

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_db():
    """Connect to SQLite database"""
    conn = sqlite3.connect(DATABASE_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    """Create all tables matching user's exact schema"""
    db = get_db()
    cursor = db.cursor()
    
    # USERS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # BEHAVIOR LOGS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS behavior_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        hour INTEGER NOT NULL,
        day_of_week INTEGER NOT NULL,
        ip_address TEXT,
        ip_prefix TEXT,
        location_country TEXT,
        location_city TEXT,
        device_fingerprint TEXT,
        device_type TEXT,
        os TEXT,
        browser TEXT,
        resource TEXT,
        action TEXT,
        session_id TEXT,
        session_duration INTEGER,
        vpn_detected INTEGER DEFAULT 0,
        proxy_detected INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    
    # USER BASELINES TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_baselines (
        user_id INTEGER PRIMARY KEY,
        baseline_data TEXT NOT NULL,
        last_updated TEXT NOT NULL,
        data_points_count INTEGER NOT NULL,
        source_log_ids TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    
    db.commit()
    db.close()
    print("✅ Tables created successfully")

def generate_fingerprint():
    """Generate device fingerprint"""
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:16]

def generate_session_id():
    """Generate session ID"""
    return hashlib.md5(str(random.random()).encode()).hexdigest()

def generate_ip():
    """Generate IP address"""
    if random.random() < 0.7:  # 70% IPv4
        return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    else:  # 30% IPv6
        parts = [f"{random.randint(0,65535):04x}" for _ in range(8)]
        return ":".join(parts)

def get_ip_prefix(ip):
    """Get IP prefix (first 3 octets for IPv4)"""
    if "." in ip:
        return ".".join(ip.split(".")[:3]) + ".0"
    return ip

def generate_users(num_users=50):
    """Generate users"""
    print(f"\n👤 Generating {num_users} users...")
    
    db = get_db()
    cursor = db.cursor()
    
    users = []
    for i in range(1, num_users + 1):
        username = f"user{i:03d}"
        email = f"user{i:03d}@example.com"
        password = "password123"  # In production, use strong passwords
        password_hash = hash_password(password)
        role = random.choice(ROLES)
        created_at = (datetime.now() - timedelta(days=random.randint(1, 180))).isoformat()
        
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (username, email, password_hash, role, created_at))
        
        user_id = cursor.lastrowid
        users.append({
            "id": user_id,
            "username": username,
            "email": email,
            "role": role
        })
    
    db.commit()
    db.close()
    print(f"✅ Created {len(users)} users")
    return users

def generate_behavior_logs(users, num_logs=500):
    """Generate behavior logs"""
    print(f"\n📋 Generating {num_logs} behavior logs...")
    
    db = get_db()
    cursor = db.cursor()
    
    base_date = datetime.now() - timedelta(days=30)
    log_ids = []
    
    for i in range(num_logs):
        # Pick random user
        user = random.choice(users)
        
        # Random timestamp within last 30 days
        random_seconds = random.randint(0, 30 * 24 * 60 * 60)
        timestamp = base_date + timedelta(seconds=random_seconds)
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        
        # Network details
        ip_address = generate_ip()
        ip_prefix = get_ip_prefix(ip_address)
        location_country = random.choice(COUNTRIES)
        location_city = random.choice(CITIES)
        
        # Device details
        device_fingerprint = generate_fingerprint()
        device_type = random.choice(DEVICE_TYPES)
        os = random.choice(OS_OPTIONS)
        browser = random.choice(BROWSERS)
        
        # Action details
        resource = random.choice(RESOURCES)
        action = random.choice(ACTIONS)
        session_id = generate_session_id()
        session_duration = random.randint(60, 3600)  # 1 min to 1 hour
        
        # VPN/Proxy detection (10% chance)
        vpn_detected = 1 if random.random() < 0.1 else 0
        proxy_detected = 1 if random.random() < 0.05 else 0
        
        cursor.execute("""
            INSERT INTO behavior_logs 
            (user_id, username, timestamp, hour, day_of_week, 
             ip_address, ip_prefix, location_country, location_city,
             device_fingerprint, device_type, os, browser,
             resource, action, session_id, session_duration,
             vpn_detected, proxy_detected)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user["id"], user["username"], timestamp.isoformat(), hour, day_of_week,
            ip_address, ip_prefix, location_country, location_city,
            device_fingerprint, device_type, os, browser,
            resource, action, session_id, session_duration,
            vpn_detected, proxy_detected
        ))
        
        log_ids.append(cursor.lastrowid)
        
        if (i + 1) % 100 == 0:
            print(f"  Generated {i + 1}/{num_logs} logs...")
    
    db.commit()
    db.close()
    print(f"✅ Created {num_logs} behavior logs")
    return log_ids

def generate_user_baselines(users, log_ids):
    """Generate user baselines"""
    print(f"\n🧠 Generating user baselines...")
    
    db = get_db()
    cursor = db.cursor()
    
    baseline_count = 0
    
    for user in users:
        # Get user's behavior logs
        cursor.execute("""
            SELECT hour, ip_prefix, location_city, location_country, 
                   device_type, os, browser, resource, session_duration
            FROM behavior_logs
            WHERE user_id = ?
        """, (user["id"],))
        
        logs = cursor.fetchall()
        if not logs:
            continue
        
        # Extract patterns
        hours = [log[0] for log in logs]
        ip_prefixes = list(set([log[1] for log in logs if log[1]]))
        cities = list(set([log[2] for log in logs if log[2]]))
        countries = list(set([log[3] for log in logs if log[3]]))
        device_types = list(set([log[4] for log in logs if log[4]]))
        os_list = list(set([log[5] for log in logs if log[5]]))
        browsers = list(set([log[6] for log in logs if log[6]]))
        resources = list(set([log[7] for log in logs if log[7]]))
        avg_session_duration = sum([log[8] for log in logs]) // len(logs) if logs else 600
        
        # Create baseline data
        baseline_data = {
            "typical_hours": hours[:10],  # Sample of hours
            "typical_ip_prefixes": ip_prefixes[:5],
            "typical_cities": cities,
            "typical_countries": countries,
            "typical_device_types": device_types,
            "typical_os": os_list,
            "typical_browsers": browsers,
            "typical_resources": resources,
            "avg_session_duration": avg_session_duration,
            "total_sessions": len(logs)
        }
        
        # Get log IDs for this user
        cursor.execute("""
            SELECT id FROM behavior_logs WHERE user_id = ? LIMIT 10
        """, (user["id"],))
        source_ids = [row[0] for row in cursor.fetchall()]
        
        cursor.execute("""
            INSERT INTO user_baselines 
            (user_id, baseline_data, last_updated, data_points_count, source_log_ids)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user["id"],
            json.dumps(baseline_data),
            datetime.now().isoformat(),
            len(logs),
            json.dumps(source_ids)
        ))
        
        baseline_count += 1
    
    db.commit()
    db.close()
    print(f"✅ Created {baseline_count} user baselines")

def show_statistics():
    """Display database statistics"""
    print("\n" + "="*70)
    print("📊 DATABASE STATISTICS")
    print("="*70)
    
    db = get_db()
    cursor = db.cursor()
    
    # Count records
    tables = ["users", "behavior_logs", "user_baselines"]
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
        count = cursor.fetchone()[0]
        print(f"  {table:25s} : {count:5d} records")
    
    # Role distribution
    print("\n" + "-"*70)
    print("User Roles:")
    cursor.execute("SELECT role, COUNT(*) as count FROM users GROUP BY role")
    for row in cursor.fetchall():
        print(f"  {row[0]:25s} : {row[1]:5d}")
    
    # VPN/Proxy stats
    print("\n" + "-"*70)
    print("Security Metrics:")
    cursor.execute("SELECT COUNT(*) as count FROM behavior_logs WHERE vpn_detected = 1")
    vpn_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) as count FROM behavior_logs WHERE proxy_detected = 1")
    proxy_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) as count FROM behavior_logs")
    total_logs = cursor.fetchone()[0]
    
    print(f"  VPN Detected              : {vpn_count:5d} / {total_logs} ({vpn_count/total_logs*100:.1f}%)")
    print(f"  Proxy Detected            : {proxy_count:5d} / {total_logs} ({proxy_count/total_logs*100:.1f}%)")
    
    # Location diversity
    cursor.execute("SELECT COUNT(DISTINCT location_country) as count FROM behavior_logs")
    countries = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT location_city) as count FROM behavior_logs")
    cities = cursor.fetchone()[0]
    print(f"  Unique Countries          : {countries:5d}")
    print(f"  Unique Cities             : {cities:5d}")
    
    print("="*70)
    
    db.close()

def main():
    """Main execution"""
    print("="*70)
    print("🚀 ZTA Data Generator - User's Exact Schema")
    print("="*70)
    print(f"Database: {DATABASE_NAME}")
    print("Tables: users, behavior_logs, user_baselines")
    print("="*70)
    
    # Create tables
    create_tables()
    
    # Generate data
    users = generate_users(num_users=50)
    log_ids = generate_behavior_logs(users, num_logs=500)
    generate_user_baselines(users, log_ids)
    
    # Show statistics
    show_statistics()
    
    print("\n✅ DATA GENERATION COMPLETE!")
    print(f"\n📁 Database created: {DATABASE_NAME}")
    print("\nYou now have:")
    print("  • 50 users with roles")
    print("  • 500 behavior logs (with VPN/proxy detection)")
    print("  • 50 user baselines (behavioral patterns)")
    print("\n🎓 Ready for ZTA model training!")

if __name__ == "__main__":
    main()
