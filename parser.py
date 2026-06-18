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