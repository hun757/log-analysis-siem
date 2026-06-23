import re

def parse_auth_log(file_path):
    events = []

    with open(file_path, "r") as file:
        for line in file:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            user_match = re.search(r"for (?:invalid user )?(\w+)", line)

            if "Failed password" in line:
                status = "failed"
            elif "Accepted password" in line:
                status = "success"
            else:
                continue

            events.append({
                "raw": line.strip(),
                "ip": ip_match.group(1) if ip_match else "unknown",
                "user": user_match.group(1) if user_match else "unknown",
                "status": status
            })

    return events
import re


def parse_auth_log_line(line):
    event = {
        "raw": line.strip(),
        "timestamp": line[:15],
        "type": None,
        "ip": "Local",
        "user": "Unknown",
        "message": line.strip()
    }

    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    if ip_match:
        event["ip"] = ip_match.group(1)

    user_match = re.search(r"for (invalid user )?(\w+)", line)
    if user_match:
        event["user"] = user_match.group(2)

    if "Failed password" in line:
        event["type"] = "FAILED_LOGIN"
        return event

    if "Accepted password" in line:
        event["type"] = "SUCCESS_LOGIN"
        return event

    if "sudo:" in line and "COMMAND=" in line:
        event["type"] = "SUDO_COMMAND"
        return event

    if "useradd" in line or "new user" in line:
        event["type"] = "USER_CREATED"
        return event

    return None
def run_detection_rules_for_event(event):
    alerts = []

    if event["type"] == "FAILED_LOGIN":
        alerts.append({
            "severity": "MEDIUM",
            "risk_score": 50,
            "type": "Failed Login",
            "ip": event.get("ip", "Unknown"),
            "message": event["message"]
        })

    elif event["type"] == "SUCCESS_LOGIN":
        alerts.append({
            "severity": "LOW",
            "risk_score": 20,
            "type": "Successful Login",
            "ip": event.get("ip", "Unknown"),
            "message": event["message"]
        })

    elif event["type"] == "SUDO_COMMAND":
        alerts.append({
            "severity": "HIGH",
            "risk_score": 75,
            "type": "Sudo Command Detected",
            "ip": event.get("ip", "Local"),
            "message": event["message"]
        })

    elif event["type"] == "USER_CREATED":
        alerts.append({
            "severity": "CRITICAL",
            "risk_score": 95,
            "type": "New User Created",
            "ip": event.get("ip", "Local"),
            "message": event["message"]
        })

    return alerts