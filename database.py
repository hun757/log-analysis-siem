import sqlite3
from datetime import datetime

DB_NAME = "siem.db"


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
def delete_alert(alert_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))

    conn.commit()
    conn.close()