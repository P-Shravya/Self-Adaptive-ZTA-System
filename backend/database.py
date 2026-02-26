# backend/database.py

import sqlite3
from pathlib import Path


# Get backend directory
BASE_DIR = Path(__file__).resolve().parent

# Define database path
DB_PATH = BASE_DIR / "dataset.db"


def get_db():
    """
    Creates connection to dataset.db.
    Enables row access as dictionary.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    """
    Optional:
    Only needed if you want backend to auto-create missing tables.
    If dataset.db already contains tables, you can leave this empty.
    """
    pass