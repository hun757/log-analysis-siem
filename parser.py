import re


# Parse an authentication log file into structured events
def parse_auth_log(file_path):
    events = []

    # Read the log file line by line
    with open(file_path, "r") as file:
        for line in file:

            # Extract the source IP address
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

            # Extract the username
            user_match = re.search(r"for (?:invalid user )?(\w+)", line)

            # Determine the login status
            if "Failed password" in line:
                status = "failed"

            elif "Accepted password" in line:
                status = "success"

            # Ignore unrelated log entries
            else:
                continue

            # Store the parsed event
            events.append({
                "raw": line.strip(),
                "ip": ip_match.group(1) if ip_match else "unknown",
                "user": user_match.group(1) if user_match else "unknown",
                "status": status
            })

    return events


# Parse a single authentication log entry for live monitoring
def parse_auth_log_line(line):

    # Default event structure
    event = {
        "raw": line.strip(),
        "timestamp": line[:15],
        "type": None,
        "ip": "Local",
        "user": "Unknown",
        "message": line.strip()
    }

    # Extract IP address (supports IPv4 and IPv6)
    ip_match = re.search(r"from ([0-9a-fA-F:\.]+)", line)
    if ip_match:
        event["ip"] = ip_match.group(1)

    # Extract username
    user_match = re.search(r"for (invalid user )?(\w+)", line)
    if user_match:
        event["user"] = user_match.group(2)

    # Detect failed SSH login
    if "Failed password" in line:
        event["type"] = "FAILED_LOGIN"
        return event

    # Detect successful SSH login
    if "Accepted password" in line:
        event["type"] = "SUCCESS_LOGIN"
        return event

    # Detect sudo command execution
    if "sudo" in line and "COMMAND=" in line:
        event["type"] = "SUDO_COMMAND"
        return event

    # Detect new user account creation
    if "useradd" in line or "new user" in line:
        event["type"] = "USER_CREATED"
        return event

    # Ignore unsupported log entries
    return None

