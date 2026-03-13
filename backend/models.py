# This file documents DB structure
# SQLite tables are created manually or via migration

"""
users(id, username, email, password_hash, role)

behavior_logs(
  id, user_id, timestamp, hour, day_of_week,
  ip_address, ip_prefix, country, city,
  device_type, os, browser,
  resource, session_id, vpn_detected
)

user_baselines(
  user_id, baseline_data, last_updated, data_points_count
)
"""
