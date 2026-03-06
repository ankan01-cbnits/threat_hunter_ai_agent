import sqlite3
import uuid
import json
from datetime import datetime

conn = sqlite3.connect("threat_hunting.db")
cursor = conn.cursor()

cursor.execute(
"""
INSERT INTO graph_state (id, created_at, state_json)
VALUES (?, ?, ?)
""",
(
    str(uuid.uuid7()),
    datetime.now(datetime.timezone.utc),
    json.dumps(state)
))

conn.commit()
conn.close()