import sqlite3
from datetime import datetime

# SQLite database file
DB_NAME = "siem.db"


# Create the alerts table if it does not exist
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT,
            risk_score INTEGER,
            alert_type TEXT,
            source_ip TEXT,
            message TEXT,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


# Check whether the alert already exists
def alert_exists(alert):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id FROM alerts
        WHERE severity = ?
        AND alert_type = ?
        AND source_ip = ?
        AND message = ?
    """, (
        alert["severity"],
        alert["type"],
        alert["ip"],
        alert["message"]
    ))

    result = cursor.fetchone()
    conn.close()

    return result is not None


# Save a new alert to the database
# Duplicate alerts are ignored
def save_alert(alert):
    if alert_exists(alert):
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            severity,
            risk_score,
            alert_type,
            source_ip,
            message,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert["severity"],
        alert["risk_score"],
        alert["type"],
        alert["ip"],
        alert["message"],
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# Retrieve all stored alerts
# Latest alerts are returned first
def get_alert_history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, severity, risk_score, alert_type, source_ip, message, created_at
        FROM alerts
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    alerts = []

    # Convert database rows into dictionaries
    for row in rows:
        alerts.append({
            "id": row[0],
            "severity": row[1],
            "risk_score": row[2],
            "type": row[3],
            "ip": row[4],
            "message": row[5],
            "created_at": row[6]
        })

    return alerts


# Delete an alert by its ID
def delete_alert(alert_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))

    conn.commit()
    conn.close()


# Search alerts using severity and/or source IP
def search_alerts(severity=None, source_ip=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    query = """
        SELECT id, severity, risk_score, alert_type, source_ip, message, created_at
        FROM alerts
        WHERE 1=1
    """

    params = []

    # Apply severity filter
    if severity:
        query += " AND severity = ?"
        params.append(severity)

    # Apply source IP filter
    if source_ip:
        query += " AND source_ip LIKE ?"
        params.append(f"%{source_ip}%")

    query += " ORDER BY id DESC"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    alerts = []

    # Convert database rows into dictionaries
    for row in rows:
        alerts.append({
            "id": row[0],
            "severity": row[1],
            "risk_score": row[2],
            "type": row[3],
            "ip": row[4],
            "message": row[5],
            "created_at": row[6]
        })

    return alerts

