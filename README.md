# Basic Express Server – Logging Keystrokes

> **Educational Use Only** – This server is part of a red‑team keylogger simulation.  
> It receives keystroke data, applies pattern detection, and displays flagged events on a live dashboard.

---

## Table of Contents

- [What This Server Does](#what-this-server-does)
- [Requirements](#requirements)
- [Quick Setup (Ubuntu)](#quick-setup-ubuntu)
- [Manual Installation (Optional)](#manual-installation-optional)
- [Running the Server](#running-the-server)
- [API Reference](#api-reference)
- [Improvements & Future Work](#improvements--future-work)

---

## What This Server Does

| Feature | Description |
|---------|-------------|
| **Keystroke logging endpoint** | Accepts POST requests with `{ "keyboardData": "..." }` |
| **Rule‑based detection** | Flags emails, passwords, credit cards, SSNs, API keys |
| **Live dashboard** | Auto‑refreshing web UI showing raw logs + flagged events |
| **Persistent storage** | Saves raw keystrokes to `keyboard_capture.txt` and flagged events to `flagged_capture.txt` |
| **Duplicate prevention** | Same credentials from the same IP are not flagged twice |

---

## Requirements

- **Ubuntu 22.04 LTS** (or any Debian‑based Linux)
- **Python 3** (for the setup script)
- **Node.js** (installed automatically by the setup script)

---

## Quick Setup (Ubuntu)

Clone the repository and run the one‑command installer:

```bash
git clone https://github.com/nickrar/express-server-basic.git
cd express-server-basic
python3 setup.py
```

This script will:

Update system packages

Install Node.js 18.x (LTS)

Install express and body-parser

Reboot the server automatically

⚠️ After reboot, you must SSH back into your server and start the server manually (see below).

## Manual Installation (Optional)

If you prefer to install dependencies yourself, use these commands:

```bash
sudo apt update && sudo apt upgrade -y
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
npm install express body-parser
```

## Running the Server

After the setup (and reboot), start the server:

```bash
cd express-server-basic
node server.js
```

You should see ASCII art and the message:
`App is listening on port 8080`

## Firewall & Access
- Open port 8080 in your firewall (e.g., Linode Firewall → TCP inbound 8080).

- Open the dashboard in your browser:
`http://<your_server_ip>:8080`

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Returns the HTML dashboard (raw logs + flagged events) |
| `GET` | `/api/logs` | Returns JSON with raw keystroke data, byte size, and line count |
| `GET` | `/api/flags` | Returns JSON with flagged events and total count |
| `POST` | `/` | Accepts `{ "keyboardData": "<text>" }` – saves and detects patterns |
| `POST` | `/api/clear` | Clears the raw log file (keyboard_capture.txt) |
| `POST` | `/api/clear-flags` | Clears flagged events file and resets duplicate prevention |

## Improvements & Future Work
This is a basic proof of concept. Possible enhancements:
- Add a database (MongoDB + Mongoose) to store historical data
- Implement authentication for the dashboard
- Add real‑time WebSocket updates instead of polling every 2 seconds
- Improve pattern detection with machine learning or more sophisticated rules
- Add screenshot capture in future

## Disclaimer
This server is part of an educational red‑team simulation.
Do not deploy on any system without authorisation.
The author assumes no liability for misuse.


