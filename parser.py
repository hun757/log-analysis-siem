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

    if "sudo" in line and "COMMAND=" in line:
        event["type"] = "SUDO_COMMAND"
        return event

    if "useradd" in line or "new user" in line:
        event["type"] = "USER_CREATED"
        return event

    return None
