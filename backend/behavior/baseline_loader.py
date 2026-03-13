from backend.database import get_db
import json

def load_user_baseline(user_id):

    db = get_db()

    row = db.execute("""
        SELECT baseline_data
        FROM user_baselines
        WHERE user_id=?
    """, (user_id,)).fetchone()

    db.close()

    if not row:
        return None

    return json.loads(row["baseline_data"])