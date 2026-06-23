# Real-Time Linux Log Analysis SIEM

A real-time Security Information and Event Management (SIEM) project built with Flask and Python. This project monitors Kali Linux system logs using `journalctl`, detects suspicious activities, stores alerts in SQLite, and visualizes security events through a web dashboard.

---

## Features

### Real-Time Monitoring

* Real-time log collection using `journalctl`
* Continuous monitoring of Kali Linux system activity
* Automatic alert generation

### Detection Rules

* Failed SSH Login Detection
* Brute Force Attack Detection
* Sudo Command Detection
* New User Creation Detection

### Dashboard

* Flask-based SOC-style dashboard
* Alert history page
* CSV export functionality
* Top IP statistics
* Auto-refresh support
* Alert severity classification

### Data Storage

* SQLite database
* Persistent alert history
* Search and filtering support

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
│
├── templates/
│   ├── dashboard.html
│   └── history.html
│
├── static/
│   └── style.css
│
├── logs/
│
├── alerts.db
│
└── README.md
```

---

## Technology Stack

* Python
* Flask
* SQLite
* Kali Linux
* systemd journal
* journalctl
* HTML
* CSS
* Chart.js

---

## Detection Rules

| Rule                  | Severity | Description                                |
| --------------------- | -------- | ------------------------------------------ |
| Failed SSH Login      | MEDIUM   | Detects failed SSH authentication attempts |
| Brute Force Attack    | CRITICAL | Detects repeated failed SSH logins         |
| Sudo Command Detected | HIGH     | Detects privileged command execution       |
| New User Created      | CRITICAL | Detects suspicious account creation        |

---

## Installation

Clone repository:

```bash
git clone https://github.com/hun757/log-analysis-siem.git
cd log-analysis-siem
```

Create virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install flask
```

---

## Running the Dashboard

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## Running Real-Time Monitoring

Open a second terminal:

```bash
sudo venv/bin/python log_monitor.py
```

The monitor will continuously read Kali Linux journal logs and generate alerts.

---

## Testing Detection Rules

### Sudo Command Detection

```bash
sudo ls
```

Expected Alert:

```text
[ALERT] Sudo Command Detected HIGH
```

### Failed SSH Login Detection

Start SSH service:

```bash
sudo systemctl start ssh
```

Attempt login using a fake account:

```bash
ssh fakeuser@localhost
```

Enter an incorrect password.

Expected Alert:

```text
[ALERT] Failed SSH Login MEDIUM
```

### Brute Force Detection

Repeat the failed SSH login attempt multiple times.

Expected Alert:

```text
[ALERT] Brute Force Attack CRITICAL
```

---

## Example Workflow

```text
User Activity
      ↓
Kali Linux Log Generation
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

## Future Improvements

* Real-time dashboard updates using WebSockets
* Geographic IP visualization
* Threat intelligence integration
* Email alert notifications
* Multi-host log collection
* Attack timeline visualization
* User behaviour analytics

---

## Purpose

This project was developed as a cybersecurity portfolio project to demonstrate:

* Real-time log monitoring
* Security event detection
* Alert management
* Linux log analysis
* SIEM concepts
* Python security tooling

---

## Author

Jeong Hun Park



