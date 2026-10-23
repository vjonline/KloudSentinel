# 🛡️ KloudSentinel : Cloud-Native SIEM with Stateful Event Correlation

> 📌 **Academic Note & Project Context**  
> This repository contains a **college mini-project** developed for an undergraduate university course (*Cybersecurity & Cloud Computing*). It was designed as a lightweight, introductory proof-of-concept (PoC) within a limited academic timeframe to demonstrate fundamental SIEM log-streaming, custom webhook integration, and stateful correlation concepts. It is **not** intended to represent a complex, enterprise-ready security architecture.

**KloudSentinel** is a cloud-native Security Information and Event Management (SIEM) architecture deployed on Microsoft Azure. It decouples heavy **log detection and rule parsing** (handled by a containerized Wazuh Manager) from **stateful threat correlation and visualization** (handled by a custom Node.js and SQLite engine).

By shifting from traditional *stateless alert generation* to *stateful threat aggregation*, KloudSentinel tracks attack persistence and frequency per source IP address in real time. When event thresholds are breached (e.g., $\ge 3$ failed authentication attempts), the platform automatically escalates incident severity to **HIGH** on a live, auto-refreshing web dashboard.

## 📁 Repository & Project Structure

```
KloudSentinel/
├── engine/
│   ├── server.js              # Node.js Express correlation engine & SQLite database handler
│   ├── package.json           # Node.js dependencies (express, sqlite3)
│   └── app.log                # Application console log output (generated at runtime)
├── wazuh-config/
│   ├── local_rules.xml        # Custom Wazuh detection rules (Rule IDs 100001 - 100006)
│   ├── ossec.conf             # Wazuh manager integration configuration snippet
│   └── custom-node            # Zero-dependency Python 3 webhook integration script
├── scripts/
│   └── start-demo.sh          # One-click startup automation script for engine & forwarder
├── docs/
│   ├── KloudSentinel_Architecture.png  # High-level system architecture diagram
│   └── Dashboard_Preview.png           # UI Preview screenshot
├── LICENSE                    # MIT License
└── README.md                  # Main project documentation

```

## 🏗️ System Architecture & Workflow

```
+-----------------------------------------------------------------------------------+
|                               AZURE VIRTUAL MACHINE                               |
|                                                                                   |
|  +-----------------------+                +------------------------------------+  |
|  | Host OS System Logs   |                | Wazuh Manager (Docker Container)   |  |
|  | (/var/log/auth.log)   | --(tail -f)--> | (/var/ossec/logs/active-responses) |  |
|  +-----------------------+                +------------------------------------+  |
|                                                              |                    |
|                                                      (local_rules.xml)            |
|                                                              v                    |
|                                                  (custom-node Webhook)            |
|                                                              |                    |
|  +-----------------------------------------------------------+                    |
|  | (HTTP POST over Docker Bridge Network: 172.17.0.1:3000)                       |
|  v                                                                                |
|  +------------------------------------+          +-----------------------------+  |
|  | Node.js Correlation Engine         | <------> | SQLite Database             |  |
|  | (server.js - Stateful Logic)       |          | (incidents.db)              |  |
|  +------------------------------------+          +-----------------------------+  |
|                   |                                                               |
|                   v                                                               |
|  +------------------------------------+                                           |
|  | Web UI Dashboard (:3000/dashboard) |                                           |
|  +------------------------------------+                                           |
+-----------------------------------------------------------------------------------+

```

### Data Pipeline Sequence

1. **Event Ingestion:** Security events (`ssh`, `sudo`, `useradd`, `passwd`, `su`) on the Azure host VM write directly to `/var/log/auth.log`.

2. **Container Streaming:** A background forwarder process (`tail -f /var/log/auth.log`) continuously pipes host OS logs into the Dockerized Wazuh Manager's active log directory (`/var/ossec/logs/active-responses.log`).

3. **Rule Matching:** The Wazuh Manager evaluates incoming logs against 6 custom XML rules (`100001`–`100006`).

4. **Webhook Dispatch:** Upon matching a rule, Wazuh triggers a zero-dependency Python integration script (`custom-node`) that POSTs JSON payloads to the host Node.js engine via the Docker bridge network gateway (`172.17.0.1:3000`).

5. **Stateful Correlation:** Node.js queries `incidents.db` (SQLite). If an open incident exists for the `(src_ip, rule_id)` tuple, it increments the event counter and evaluates severity escalation thresholds. If no record exists, it creates a new incident.

6. **Live Visualization:** The web UI (`/dashboard`) queries SQLite and updates the live incident table every 3 seconds.

## 🔒 Security Detection Rules Matrix

KloudSentinel monitors six key authentication and privilege escalation indicators configured in `/var/ossec/etc/rules/local_rules.xml`:


| **Rule ID** | **Parent Rule ID** | **Category** | **Trigger Event Pattern** | **Base Severity** | **Escalation Threshold** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`100001`** | `5710` | Brute Force | Failed SSH password attempt | `MEDIUM` | Escalates to **HIGH** at $\ge 3$ events |
| **`100002`** | `5715` | Remote Access | Successful SSH login | `LOW` | Increments session count |
| **`100003`** | `5402` | Privilege Escalation | Execution of `sudo` command | `LOW` | Tracks elevated command history |
| **`100004`** | `5902` | Persistence | New local user created (`useradd`) | `MEDIUM` | Flags account creation |
| **`100005`** | `5901` | Credential Manipulation | Password updated (`passwd`) | `MEDIUM` | Flags password modification |
| **`100006`** | `5301, 5302` | Lateral Movement | Switch user attempt (`su`) | `LOW` | Tracks user context switching |

## ✨ Key Technical Innovations

* **Zero-Dependency Webhook Bridge:** Built using Python 3's native `urllib.request` library. Eliminates third-party package dependencies (`requests`, `pip`), making the webhook $100\%$ resilient against container resets and base image updates.

* **Alert Fatigue Reduction:** Aggregates repetitive attack streams (e.g., 30+ automated SSH botnet dictionary attempts) into a single, managed incident row rather than emitting dozens of uncoordinated alerts.

* **Persistent State Tracking:** Uses a local disk-backed SQLite database (`incidents.db`) to preserve incident states, historical attack counts, and severity badges across application restarts and VM reboots.

* **Host-to-Container Bridge Network Routing:** Routes containerized webhook triggers directly to the host VM interface over Docker's bridge network gateway (`172.17.0.1:3000`).

## 🚀 Quick Start & Deployment Guide

### Prerequisites

* Microsoft Azure Virtual Machine running **Ubuntu 22.04 LTS**

* Docker & Docker Compose installed

* Node.js (v18+) & NPM

### Step 1: Clone the Repository

```
git clone https://github.com/YOUR_USERNAME/KloudSentinel.git
cd KloudSentinel

```

### Step 2: Configure Wazuh Integration

1. Deploy the Wazuh Docker single-node stack:

   ```
   docker-compose -f wazuh-docker/single-node/docker-compose.yml up -d
   
   ```

2. Copy custom rules to the Wazuh container:

   ```
   docker cp wazuh-config/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
   
   ```

3. Copy the zero-dependency Python script to the integrations directory and adjust permissions:

   ```
   docker cp wazuh-config/custom-node single-node-wazuh.manager-1:/var/ossec/integrations/custom-node
   docker exec -it single-node-wazuh.manager-1 chmod 750 /var/ossec/integrations/custom-node
   docker exec -it single-node-wazuh.manager-1 chown root:wazuh /var/ossec/integrations/custom-node
   
   ```

4. Append the integration block to `ossec.conf` inside the container:

   ```
   <integration>
     <name>custom-node</name>
     <hook_url>http://172.17.0.1:3000/api/alerts</hook_url>
     <rule_id>100001, 100002, 100003, 100004, 100005, 100006</rule_id>
     <alert_format>json</alert_format>
   </integration>
   
   ```

5. Restart the Wazuh Manager:

   ```
   docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
   
   ```

### Step 3: Initialize the KloudSentinel Engine

1. Install Node.js dependencies:

   ```
   cd engine
   npm install
   
   ```

2. Make the startup script executable and run it:

   ```
   chmod +x ../scripts/start-demo.sh
   ../scripts/start-demo.sh
   
   ```

### Step 4: Access the Live Dashboard

Navigate to `http://<YOUR_AZURE_VM_IP_OR_DNS>:3000/dashboard` in your browser.

## 📡 API Reference

### `POST /api/alerts`

Ingestion endpoint for alert payloads dispatched by Wazuh's `custom-node` webhook.

* **Payload Example:**

  ```
  {
    "data": { "srcip": "109.160.32.105" },
    "rule": {
      "id": "100001",
      "description": "Custom Detection: SSH authentication failure detected on host."
    }
  }
  
  ```

* **Response:** `200 OK` `{"status": "received"}`

### `GET /dashboard`

Renders the HTML live security incident table. Features automatic page refresh every 3 seconds (`<meta http-equiv="refresh" content="3">`).

### `POST /api/clear`

Clears all records from `incidents.db` to reset the dashboard state for demonstration runs.

## 🧪 Demonstration & Testing Commands

| **Scenario** | **Terminal Command on Host VM** | **Expected UI Result** |
| :--- | :--- | :--- |
| **Brute Force SSH** | `ssh invaliduser@<VM_DNS>` *(Enter wrong password 3 times)* | Count increments to 4; Severity escalates to **HIGH** |
| **Privilege Command** | `sudo ls` | Logs event under Rule `100003` with **LOW** severity |
| **Account Creation** | `sudo useradd testuser` | Logs event under Rule `100004` with **MEDIUM** severity |
| **Password Change** | `sudo passwd venom` | Logs event under Rule `100005` with **MEDIUM** severity |

