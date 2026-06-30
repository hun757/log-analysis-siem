import subprocess
from parser import parse_auth_log_line
from detector import run_detection_rules_for_event
from database import save_alert


# Monitor live system logs using journalctl
def monitor_journal():
    print("[+] Monitoring started: journalctl -f")

    # Start journalctl in follow mode
    # -f keeps reading new logs in real time
    # -n 0 prevents old logs from being printed at startup
    process = subprocess.Popen(
        ["journalctl", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # Read each new log line from journalctl
    for line in process.stdout:
        line = line.strip()

        # Ignore empty lines
        if not line:
            continue

        print("[LOG]", line)

        # Parse the raw log line into a structured event
        event = parse_auth_log_line(line)

        # Run detection rules only if the line matches a known event type
        if event:
            alerts = run_detection_rules_for_event(event)

            # Save and print generated alerts
            for alert in alerts:
                save_alert(alert)
                print("[ALERT]", alert["type"], alert["severity"])


# Run the live monitor when this file is executed directly
if __name__ == "__main__":
    monitor_journal()

