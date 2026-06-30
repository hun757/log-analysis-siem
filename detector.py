from collections import Counter, defaultdict, deque
import time


# Track failed login timestamps for each IP address
failed_login_tracker = defaultdict(deque)


# Detect brute force attempts from uploaded log files
def detect_brute_force(events):
    alerts = []

    # Collect IP addresses from failed login events
    failed_ips = [
        event["ip"]
        for event in events
        if event["status"] == "failed"
    ]

    # Count failed login attempts per IP
    ip_count = Counter(failed_ips)

    # Generate an alert if an IP has 5 or more failed attempts
    for ip, count in ip_count.items():
        if count >= 5:
            alerts.append({
                "severity": "HIGH",
                "risk_score": 90,
                "type": "Brute Force Attempt",
                "ip": ip,
                "message": f"{ip} made {count} failed login attempts."
            })

    return alerts


# Detect login attempts using privileged account names
def detect_admin_login_attempts(events):
    alerts = []

    # Common administrator account names
    admin_users = ["root", "admin", "administrator"]

    for event in events:
        if event["user"].lower() in admin_users:
            alerts.append({
                "severity": "MEDIUM",
                "risk_score": 60,
                "type": "Admin Account Login Attempt",
                "ip": event["ip"],
                "message": f"Login attempt detected for admin account: {event['user']}"
            })

    return alerts


# Run all detection rules for uploaded log analysis
def run_detection_rules(events):
    alerts = []

    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_admin_login_attempts(events))

    return alerts


# Run detection rules for a single real-time log event
def run_detection_rules_for_event(event):
    alerts = []

    # Detect failed SSH login events
    if event["type"] == "FAILED_LOGIN":
        ip = event.get("ip", "Unknown")
        now = time.time()

        # Store the timestamp of the failed login attempt
        failed_login_tracker[ip].append(now)

        # Keep only failed attempts within the last 5 minutes
        while failed_login_tracker[ip] and now - failed_login_tracker[ip][0] > 300:
            failed_login_tracker[ip].popleft()

        # Raise a critical alert if 5 or more failures occur within 5 minutes
        if len(failed_login_tracker[ip]) >= 5:
            alerts.append({
                "severity": "CRITICAL",
                "risk_score": 95,
                "type": "Brute Force Attack",
                "ip": ip,
                "message": f"{ip} made {len(failed_login_tracker[ip])} failed SSH login attempts within 5 minutes."
            })

        # Otherwise, log it as a medium-risk failed login
        else:
            alerts.append({
                "severity": "MEDIUM",
                "risk_score": 50,
                "type": "Failed SSH Login",
                "ip": ip,
                "message": event["message"]
            })

    # Detect successful SSH login events
    elif event["type"] == "SUCCESS_LOGIN":
        alerts.append({
            "severity": "LOW",
            "risk_score": 20,
            "type": "Successful SSH Login",
            "ip": event.get("ip", "Unknown"),
            "message": event["message"]
        })

    # Detect sudo command usage
    elif event["type"] == "SUDO_COMMAND":
        alerts.append({
            "severity": "HIGH",
            "risk_score": 75,
            "type": "Sudo Command Detected",
            "ip": event.get("ip", "Local"),
            "message": event["message"]
        })

    # Detect new user account creation
    elif event["type"] == "USER_CREATED":
        alerts.append({
            "severity": "CRITICAL",
            "risk_score": 95,
            "type": "New User Created",
            "ip": event.get("ip", "Local"),
            "message": event["message"]
        })

    return alerts

