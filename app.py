from collections import Counter
from flask import Flask, render_template, request, redirect
import os
from database import init_db, save_alert, get_alert_history, delete_alert
from parser import parse_auth_log
from detector import run_detection_rules
from database import init_db, save_alert, get_alert_history

app = Flask(__name__)

UPLOAD_FOLDER = "logs"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

init_db()


@app.route("/", methods=["GET", "POST"])
def dashboard():
    log_file = "logs/sample_auth.log"

    if request.method == "POST":
        uploaded_file = request.files.get("logfile")

        if uploaded_file and uploaded_file.filename:
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], uploaded_file.filename)
            uploaded_file.save(file_path)
            log_file = file_path

    events = parse_auth_log(log_file)
    alerts = run_detection_rules(events)

    if request.method == "POST":
        for alert in alerts:
            save_alert(alert)

    ip_counts = Counter(event["ip"] for event in events)
    top_ips = ip_counts.most_common(5)

    return render_template(
        "dashboard.html",
        events=events,
        alerts=alerts,
        total_events=len(events),
        total_alerts=len(alerts),
        top_ips=top_ips
    )


@app.route("/history")
def history():
    alerts = get_alert_history()

    return render_template(
        "history.html",
        alerts=alerts
    )

@app.route("/delete/<int:alert_id>", methods=["POST"])
def delete(alert_id):
    delete_alert(alert_id)
    return redirect("/history")

if __name__ == "__main__":
    app.run(debug=True)