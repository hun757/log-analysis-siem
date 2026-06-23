import time
from parser import parse_auth_log_line
from detector import run_detection_rules_for_event
from database import save_alert


LOG_PATH = "/var/log/auth.log"


def monitor_log():
    print(f"[+] Monitoring started: {LOG_PATH}")

    with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            print("[LOG]", line.strip())

            event = parse_auth_log_line(line)

            if event:
                alerts = run_detection_rules_for_event(event)

                for alert in alerts:
                    save_alert(alert)
                    print("[ALERT]", alert["type"], alert["severity"])


if __name__ == "__main__":
    monitor_log()