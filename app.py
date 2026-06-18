from collections import Counter
from flask import Flask, render_template, request
import os

from parser import parse_auth_log
from detector import run_detection_rules

app = Flask(__name__)

UPLOAD_FOLDER = "logs"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


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


if __name__ == "__main__":
    app.run(debug=True)