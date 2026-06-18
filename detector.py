from collections import Counter


def detect_brute_force(events):
    alerts = []

    failed_ips = [
        event["ip"]
        for event in events
        if event["status"] == "failed"
    ]

    ip_count = Counter(failed_ips)

    for ip, count in ip_count.items():
        if count >= 5:
            alerts.append({
                "severity": "HIGH",
                "risk_score": 90,
                "type": "Brute Force Attempt",
                "ip": ip,
                "message": f"{ip} made {count} failed login attempts."
            })

    return alerts


def detect_admin_login_attempts(events):
    alerts = []
    admin_users = ["root", "admin", "administrator"]

    for event in events:
        if event["user"].lower() in admin_users:
            alerts.append({
                "severity": "MEDIUM",
                "risk_score": 60,
                "type": "Admin Account Login Attempt",
                "ip": event["ip"],
                "message": f"Login attempt detected for admin account: {event['user']}"
            })

    return alerts


def run_detection_rules(events):
    alerts = []
    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_admin_login_attempts(events))
    return alerts