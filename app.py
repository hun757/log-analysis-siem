from collections import Counter
from flask import Flask, render_template, request, redirect, Response
import os
from database import init_db, save_alert, get_alert_history, delete_alert, search_alerts
from parser import parse_auth_log
from detector import run_detection_rules
import csv
import io


# Create the Flask application
app = Flask(__name__)

# Configure the upload directory for log files
UPLOAD_FOLDER = "logs"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Initialize the SQLite database
init_db()


# Main dashboard
# GET: Display dashboard
# POST: Upload and analyze a log file
@app.route("/", methods=["GET", "POST"])
def dashboard():
    # Store parsed log events
    events = []

    # Store detected security alerts
    alerts = []

    # Handle uploaded log file
    if request.method == "POST":
        uploaded_file = request.files.get("logfile")

        # Ensure a valid file was uploaded
        if uploaded_file and uploaded_file.filename:

            # Save the uploaded log file
            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                uploaded_file.filename
            )
            uploaded_file.save(file_path)

            # Parse authentication log into structured events
            events = parse_auth_log(file_path)

            # Run detection rules against parsed events
            alerts = run_detection_rules(events)

            # Save detected alerts to the database
            for alert in alerts:
                save_alert(alert)

    # Retrieve all stored alerts
    all_alerts = get_alert_history()

    # Display only the latest five alerts
    recent_alerts = all_alerts[:5]

    # Count alert occurrences by source IP
    # Ignore local or unknown addresses
    ip_counts = Counter(
        alert["ip"]
        for alert in all_alerts
        if alert["ip"]
        and alert["ip"] not in ["Local", "unknown", "Unknown"]
    )

    # Select the top five source IPs
    top_ips = ip_counts.most_common(5)

    # Prepare data for the dashboard chart
    ip_labels = [ip for ip, count in top_ips]
    ip_values = [count for ip, count in top_ips]

    # Render the dashboard with analysis results
    return render_template(
        "dashboard.html",
        events=events,
        alerts=alerts,
        recent_alerts=recent_alerts,
        total_events=len(events),
        total_alerts=len(all_alerts),
        top_ips=top_ips,
        ip_labels=ip_labels,
        ip_values=ip_values
    )


# Alert history page
@app.route("/history")
def history():

    # Get search filters from the URL
    severity = request.args.get("severity")
    source_ip = request.args.get("source_ip")

    # Search alerts if filters are provided
    if severity or source_ip:
        alerts = search_alerts(severity, source_ip)

    # Otherwise, load all alerts
    else:
        alerts = get_alert_history()

    # Render the history page
    return render_template(
        "history.html",
        alerts=alerts,
        selected_severity=severity or "",
        searched_ip=source_ip or ""
    )


# Delete a selected alert
@app.route("/delete/<int:alert_id>", methods=["POST"])
def delete(alert_id):

    # Remove the alert from the database
    delete_alert(alert_id)

    # Redirect back to the history page
    return redirect("/history")


# Export alert history as a CSV file
@app.route("/export")
def export_alerts():

    # Load all alerts
    alerts = get_alert_history()

    # Create an in-memory CSV file
    output = io.StringIO()
    writer = csv.writer(output)

    # Write CSV header
    writer.writerow([
        "ID",
        "Severity",
        "Risk Score",
        "Type",
        "Source IP",
        "Message",
        "Created At"
    ])

    # Write alert records
    for alert in alerts:
        writer.writerow([
            alert["id"],
            alert["severity"],
            alert["risk_score"],
            alert["type"],
            alert["ip"],
            alert["message"],
            alert["created_at"]
        ])

    # Create a downloadable CSV response
    response = Response(
        output.getvalue(),
        mimetype="text/csv"
    )

    # Set the downloaded filename
    response.headers["Content-Disposition"] = (
        "attachment; filename=alert_history.csv"
    )

    return response


# Run the Flask development server
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)