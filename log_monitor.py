import subprocess
from parser import parse_auth_log_line
from detector import run_detection_rules_for_event
from database import save_alert


def monitor_journal():
    print("[+] Monitoring started: journalctl -f")

    process = subprocess.Popen(
        ["journalctl", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    for line in process.stdout:
        line = line.strip()

        if not line:
            continue

        print("[LOG]", line)

        event = parse_auth_log_line(line)

        if event:
            alerts = run_detection_rules_for_event(event)

            for alert in alerts:
                save_alert(alert)
                print("[ALERT]", alert["type"], alert["severity"])


if __name__ == "__main__":
    monitor_journal()