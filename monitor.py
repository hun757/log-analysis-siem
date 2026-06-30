import time
from collections import defaultdict

from parser import parse_auth_log
from database import init_db, save_alert

# Path to the live authentication log file
LOG_FILE = "logs/live_auth.log"

# Track failed login attempts by IP address
failed_login_count = defaultdict(int)


# Continuously monitor new lines appended to the log file
def follow_log_file(file_path):
    with open(file_path, "r") as file:

        # Move to the end of the file to monitor only new log entries
        file.seek(0, 2)

        while True:
            line = file.readline()

            # Wait if no new log entry is available
            if not line:
                time.sleep(1)
                continue

            yield line


# Analyze a single live log event
def analyze_live_event(event):
    alerts = []

    ip = event["ip"]
    user = event["user"]
    status = event["status"]

    # Detect repeated failed login attempts
    if status == "failed":
        failed_login_count[ip] += 1

        # Raise an alert after five failed attempts
        if failed_login_count[ip] >= 5:
            alerts.append({
                "severity": "HIGH",
                "risk_score": 90,
                "type": "Live Brute Force Attempt",
                "ip": ip,
                "message": f"{ip} made {failed_login_count[ip]} failed login attempts."
            })

    # Detect login attempts targeting privileged accounts
    if user.lower() in ["root", "admin", "administrator"]:
        alerts.append({
            "severity": "MEDIUM",
            "risk_score": 60,
            "type": "Live Admin Account Login Attempt",
            "ip": ip,
            "message": f"Login attempt detected for admin account: {user}"
        })

    return alerts


# Start the live log monitoring service
def start_monitor():

    # Initialize the database
    init_db()

    print("[INFO] Live log monitor started.")
    print("[INFO] Watching new lines only.")
    print("[INFO] Press CTRL+C to stop.")

    try:
        # Monitor new log entries continuously
        for line in follow_log_file(LOG_FILE):

            # Write the current log line to a temporary file
            temp_file = "logs/temp_live.log"

            with open(temp_file, "w") as file:
                file.write(line)

            # Parse the temporary log file
            events = parse_auth_log(temp_file)

            # Analyze each parsed event
            for event in events:
                alerts = analyze_live_event(event)

                # Save detected alerts to the database
                for alert in alerts:
                    save_alert(alert)
                    print(f"[ALERT] {alert['severity']} - {alert['message']}")

    # Stop monitoring gracefully
    except KeyboardInterrupt:
        print("[INFO] Live log monitor stopped.")


# Run the live monitor when executed directly
if __name__ == "__main__":
    start_monitor()

