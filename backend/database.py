import sqlite3
from datetime import datetime

DATABASE_NAME = "users.db"

# Function to connect to SQLite
def get_db():
    conn = sqlite3.connect(DATABASE_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Function to create all tables
def create_tables():
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
def insert_sample_data():
db = get_db()
cursor = db.cursor()
# Insert sample users
    users = [
        ("Alice", "alice@example.com", "hashed_pw_1", "user"),
        ("Bob", "bob@example.com", "hashed_pw_2", "admin"),
        ("Charlie", "charlie@example.com", "hashed_pw_3", "user"),
        ("David", "david@example.com", "hashed_pw_4", "security"),
        ("Eve", "eve@example.com", "hashed_pw_5", "user")
    ]
    cursor.executemany("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)", users)
# Insert sample behavior logs
    logs = [
        (1, "Alice", datetime.now().isoformat(), 10, 1, "192.168.1.10", "192.168.1", "India", "Hyderabad", "device_fp_1", "Laptop", "Windows", "Chrome", "/dashboard", "login", "sess1", 30, 0, 0),
        (2, "Bob", datetime.now().isoformat(), 12, 2, "192.168.1.20", "192.168.1", "India", "Hyderabad", "device_fp_2", "Phone", "Android", "Chrome", "/settings", "login", "sess2", 15, 0, 0),
        (3, "Charlie", datetime.now().isoformat(), 14, 3, "192.168.1.30", "192.168.1", "India", "Hyderabad", "device_fp_3", "Laptop", "MacOS", "Safari", "/profile", "update", "sess3", 20, 0, 0),
        (4, "David", datetime.now().isoformat(), 16, 4, "192.168.1.40", "192.168.1", "India", "Hyderabad", "device_fp_4", "Laptop", "Windows", "Firefox", "/dashboard", "login", "sess4", 25, 0, 0),
        (5, "Eve", datetime.now().isoformat(), 18, 5, "192.168.1.50", "192.168.1", "India", "Hyderabad", "device_fp_5", "Tablet", "iOS", "Safari", "/profile", "update", "sess5", 10, 0, 0)
    ]
    cursor.executemany("""INSERT INTO behavior_logs 
        (user_id, username, timestamp, hour, day_of_week, ip_address, ip_prefix, location_country, location_city, device_fingerprint, device_type, os, browser, resource, action, session_id, session_duration, vpn_detected, proxy_detected) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", logs)
    
    # Insert sample user baselines
    baselines = [
        (1, '{"login_hours":[9,10,11]}', datetime.now().isoformat(), 3, "1,2,3"),
        (2, '{"login_hours":[12,13]}', datetime.now().isoformat(), 2, "4,5"),
        (3, '{"login_hours":[14,15]}', datetime.now().isoformat(), 2, "6,7"),
        (4, '{"login_hours":[16,17]}', datetime.now().isoformat(), 2, "8,9"),
        (5, '{"login_hours":[18,19]}', datetime.now().isoformat(), 2, "10,11")
    ]
    cursor.executemany("INSERT INTO user_baselines (user_id, baseline_data, last_updated, data_points_count, source_log_ids) VALUES (?, ?, ?, ?, ?)", baselines)
    db.commit()
    db.close()
    print("Sample data inserted successfully!")

# Run the functions
if __name__ == "__main__":
    create_tables()
    insert_sample_data()

    
