import time

from parser import parse_auth_log
from detector import run_detection_rules
from database import init_db, save_alert

LOG_FILE = "logs/live_auth.log"


def follow_log_file(file_path):
    with open(file_path, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            yield line


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
            alerts = run_detection_rules(events)

            for alert in alerts:
                save_alert(alert)
                print(f"[ALERT] {alert['severity']} - {alert['message']}")

    except KeyboardInterrupt:
        print("[INFO] Live log monitor stopped.")


if __name__ == "__main__":
    start_monitor()