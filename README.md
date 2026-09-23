# Real-Time Linux Log Analysis SIEM

A lightweight Security Information and Event Management (SIEM) system built with **Python and Flask**.

The project continuously monitors Linux system logs using `journalctl`, detects suspicious security events, stores generated alerts in SQLite, and presents them through a SOC-style web dashboard.

It was developed as a cybersecurity portfolio project to demonstrate practical experience with **Linux log analysis, security event detection, alert management, and SIEM concepts**.

---

## Overview

The SIEM monitors activity generated on a Kali Linux system and processes new journal logs in real time.

Detected security events are classified by severity and stored in a SQLite database. The Flask web application then displays the alerts through a dashboard where users can review recent security activity and alert history.

### Monitoring Workflow

```text
User Activity
      ↓
Kali Linux
      ↓
systemd journal
      ↓
journalctl
      ↓
log_monitor.py
      ↓
parser.py
      ↓
detector.py
      ↓
SQLite Database
      ↓
Flask Dashboard
```

---

## Features

### Real-Time Log Monitoring

* Collects Linux system logs using `journalctl`
* Continuously monitors system activity
* Processes new log entries automatically
* Generates alerts when suspicious activity is detected

### Security Detection Rules

The system currently detects several common Linux security events.

| Detection Rule        | Severity | Description                                |
| --------------------- | -------- | ------------------------------------------ |
| Failed SSH Login      | MEDIUM   | Detects failed SSH authentication attempts |
| Brute Force Attack    | CRITICAL | Detects repeated failed SSH login attempts |
| Sudo Command Detected | HIGH     | Detects privileged command execution       |
| New User Created      | CRITICAL | Detects suspicious account creation        |

### SOC-Style Dashboard

The Flask web interface provides:

* Recent security alerts
* Alert history
* Alert severity classification
* Search and filtering
* Top source IP statistics
* Automatic dashboard refresh
* CSV export functionality

### Persistent Alert Storage

Security alerts are stored in a SQLite database so that previously detected events can be reviewed later.

---

## Technology Stack

| Technology      | Purpose                              |
| --------------- | ------------------------------------ |
| Python          | Core application and detection logic |
| Flask           | Web dashboard                        |
| SQLite          | Alert storage                        |
| Kali Linux      | Monitored Linux environment          |
| systemd journal | Linux event logging                  |
| journalctl      | Log collection                       |
| HTML / CSS      | Dashboard interface                  |
| Chart.js        | Dashboard visualisation              |

---

## Project Structure

```text
log-analysis-siem/
│
├── app.py
├── database.py
├── detector.py
├── parser.py
├── log_monitor.py
├── monitor.py
│
├── templates/
│   ├── dashboard.html
│   └── history.html
│
├── static/
│   └── style.css
│
├── requirements.txt
├── .gitignore
└── README.md
```

### Main Components

**`app.py`**

Runs the Flask web application and provides the dashboard interface.

**`log_monitor.py`**

Continuously reads new Linux journal entries and sends them through the analysis pipeline.

**`parser.py`**

Processes raw log entries into a format that can be analysed by the detection system.

**`detector.py`**

Applies detection rules and identifies suspicious activity.

**`database.py`**

Handles alert storage and retrieval using SQLite.

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/hun757/log-analysis-siem.git
cd log-analysis-siem
```

### 2. Create a Python Virtual Environment

```bash
python3 -m venv venv
```

Activate the environment:

```bash
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Running the SIEM

The monitoring component and Flask dashboard run separately.

### Terminal 1 — Start the Dashboard

```bash
python app.py
```

Open the dashboard in a browser:

```text
http://127.0.0.1:5000
```

### Terminal 2 — Start Real-Time Monitoring

```bash
sudo venv/bin/python log_monitor.py
```

The monitoring process will continuously read Linux journal logs and generate alerts when configured detection rules are triggered.

---

## Testing Detection Rules

The detection rules can be tested by generating controlled Linux security events.

### Sudo Command Detection

Run:

```bash
sudo ls
```

Expected alert:

```text
[ALERT] Sudo Command Detected HIGH
```

---

### Failed SSH Login Detection

Start the SSH service:

```bash
sudo systemctl start ssh
```

Attempt to log in using a non-existent account:

```bash
ssh fakeuser@localhost
```

Enter an incorrect password.

Expected alert:

```text
[ALERT] Failed SSH Login MEDIUM
```

---

### Brute Force Detection

Repeat failed SSH login attempts multiple times.

Expected alert:

```text
[ALERT] Brute Force Attack CRITICAL
```

---

## How It Works

The project separates monitoring, parsing, detection, storage, and presentation into different components.

```text
Linux Activity
      │
      ▼
systemd journal
      │
      ▼
journalctl
      │
      ▼
Log Monitor
      │
      ▼
Log Parser
      │
      ▼
Detection Engine
      │
      ▼
SQLite Alert Database
      │
      ▼
Flask SOC Dashboard
```

This structure makes it easier to extend individual parts of the project without tightly coupling the monitoring and dashboard components.

---

## Dashboard

The web dashboard is designed to provide a simple SOC-style view of detected security activity.

It includes alert information such as:

* Detection type
* Severity
* Alert history
* Source IP statistics
* Recent events

> Dashboard screenshots can be added here to provide a quick visual demonstration of the project.

---

## Future Improvements

Possible future improvements include:

* Real-time dashboard updates using WebSockets
* Geographic IP visualisation
* Threat intelligence integration
* Email alert notifications
* Multi-host log collection
* Attack timeline visualisation
* User behaviour analytics

---

## Project Purpose

This project was created to develop and demonstrate practical cybersecurity skills involving:

* Linux security monitoring
* Linux log analysis
* Security event detection
* SIEM architecture
* Alert classification
* Python security tooling
* Flask web development
* Security data storage and visualisation

---

## Author

**Jeong Hun Park**

Cybersecurity student interested in security monitoring, SIEM, threat detection, and Blue Team security.
