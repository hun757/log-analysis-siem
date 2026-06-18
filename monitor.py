import time
from collections import defaultdict

from parser import parse_auth_log
from database import init_db, save_alert

LOG_FILE = "logs/live_auth.log"

failed_login_count = defaultdict(int)


def follow_log_file(file_path):
    with open(file_path, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            yield line


def analyze_live_event(event):
    alerts = []

    ip = event["ip"]
    user = event["user"]
    status = event["status"]

    if status == "failed":
        failed_login_count[ip] += 1

        if failed_login_count[ip] >= 5:
            alerts.append({
                "severity": "HIGH",
                "risk_score": 90,
                "type": "Live Brute Force Attempt",
                "ip": ip,
                "message": f"{ip} made {failed_login_count[ip]} failed login attempts."
            })

    if user.lower() in ["root", "admin", "administrator"]:
        alerts.append({
            "severity": "MEDIUM",
            "risk_score": 60,
            "type": "Live Admin Account Login Attempt",
            "ip": ip,
            "message": f"Login attempt detected for admin account: {user}"
        })

    return alerts


def start_monitor():
    init_db()

    print("[INFO] Live log monitor started.")
    print("[INFO] Watching new lines only.")
    print("[INFO] Press CTRL+C to stop.")

    try:
        for line in follow_log_file(LOG_FILE):
            temp_file = "logs/temp_live.log"

            with open(temp_file, "w") as file:
                file.write(line)

            events = parse_auth_log(temp_file)

            for event in events:
                alerts = analyze_live_event(event)

                for alert in alerts:
                    save_alert(alert)
                    print(f"[ALERT] {alert['severity']} - {alert['message']}")

    except KeyboardInterrupt:
        print("[INFO] Live log monitor stopped.")


if __name__ == "__main__":
    start_monitor()