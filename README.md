# 🛡️ AI-NSMS: Intelligent Network Security Monitoring System using AI

An enterprise-grade, real-time Security Operations Center (SOC) platform powered by Artificial Intelligence and Machine Learning for continuous network flow capture, forensic session analysis, unsupervised anomaly detection, and automated threat classification.

---

## 🎯 Target Threat Taxonomy & Scope

| Threat Class | Severity Tier | Threat Score Base | Primary Attack Signatures |
|---|:---:|:---:|---|
| **DDoS Attack** | `CRITICAL` | `95 / 100` | Volumetric packet floods, extreme packet rates ($\ge 1500\text{ pps}$), traffic saturation |
| **Port Scanning** | `HIGH` | `70 / 100` | Multi-port reconnaissance sweeps ($\ge 10\text{ ports}$ in window), service probing |
| **Brute Force** | `HIGH` | `85 / 100` | Repeated credential cracking bursts on auth ports (SSH `22`, FTP `21`, RDP `3389`, DBs) |
| **Unknown Threat** | `MEDIUM` | `50 / 100` | Statistical anomalies flagged by Isolation Forest ($\text{score} \le -0.05$) with atypical distributions |
| **Normal Traffic** | `LOW` | `0 / 100` | Legitimate baseline communications conforming to standard network profiles |

---

## 🔬 Multi-Tiered AI & Decision Architecture

AI-NSMS employs a multi-tiered defense-in-depth detection architecture designed to eliminate false positives on legitimate background traffic while maintaining high sensitivity to genuine network attacks:

```text
[ Real Network Interface (e.g. wlp108s0 / eth0 / lo) ]
                         ↓
[ Scapy Real-Time Packet Sniffer (Promiscuous BPF Filter) ]
                         ↓
[ Canonical Bidirectional Session Flow Table (1.0s Teardown Grace Period) ]
                         ↓
[ 11-Feature Flow Vector Extraction (Zero-Rate Boundary Protection) ]
                         ↓
[ StandardScaler Normalization (Standard 9-Numerical Vector) ]
                         ↓
       ┌─────────────────┴─────────────────┐
       ▼                                   ▼
[ Multi-Class Random Forest ]     [ Isolation Forest Anomaly ]
 (Calibrated Posterior Probas)        (Inlier/Outlier Score)
       └─────────────────┬─────────────────┘
                         ↓
[ Multi-Tiered Decision Engine & Arbitration (pipeline.py) ]
 • Tier 1: Behavioral Hard Safety Floors (DDoS: ≥ 50 pkts & ≥ 50 KB & ≥ 1500 pps)
 • Tier 2: Corroborated Attack Classification (Calibrated Threshold ≥ 0.55)
 • Tier 3: Statistical Anomaly Isolation (IsolationForest ≤ -0.05 → UNKNOWN)
 • Tier 4: Baseline Normal Traffic Default (Threat Score: 0/100, No False Alerts)
                         ↓
[ Explainable Threat Scoring Matrix (0–100) & Forensic Indicators ]
                         ↓
[ Deduplication & Dual-Layer Storage ]
 • network_flows: Records 100% of network traffic telemetry for SOC charts.
 • detections: Records all classifications (Normal, Unknown, Threat, Attack).
 • alerts: Creates actionable alerts for confirmed threats with 15s deduplication.
                         ↓
[ Flask RESTful API & Server-Sent Events (SSE) Telemetry Stream ]
                         ↓
[ Dark Cyber SOC Dashboard & Live Monitoring Web Console ]
```

---

## 📊 Extracted 11 Network Flow Features

1. **`Protocol`**: Transport protocol (`TCP`, `UDP`, `ICMP`, `OTHER`).
2. **`Destination Port`**: Target service port (e.g. `80`, `443`, `53`, `22`).
3. **`Total Flow Size`**: Total bytes transferred in bidirectional session.
4. **`Average Packet Size`**: Mean payload length across the session ($\text{bytes} / \text{packets}$).
5. **`Standard Deviation of Packet Size`**: Variance of packet lengths.
6. **`Packet Count`**: Total packets exchanged in both directions.
7. **`Flow Duration`**: Active session duration in seconds ($t_{\text{last}} - t_{\text{first}}$).
8. **`Average Inter-Arrival Time (IAT)`**: Mean time interval between consecutive packets.
9. **`Maximum Inter-Arrival Time (IAT)`**: Peak delay between packets.
10. **`Packets Per Second (PPS)`**: Packet transmission rate ($\text{pkt\_count} / \text{duration}$).
11. **`Bytes Per Second (BPS)`**: Throughput rate ($\text{total\_bytes} / \text{duration}$).

---

## 🗄️ Database Architecture & PostgreSQL Support

The platform utilizes a structured relational database (`schema.sql`) supporting both **PostgreSQL** and local **SQLite** (`data/ids_database.db`):

- **`users`**: Authentication, RBAC (`ADMIN`, `SECURITY_ANALYST`), bcrypt password hashes.
- **`network_flows`**: Full 11-feature flow telemetry records (raw payloads are never stored for privacy).
- **`detections`**: AI inference results, model probabilities, threat score, severity, indicators, and session tracking.
- **`alerts`**: Actionable SOC security incident queue (`NEW`, `ACKNOWLEDGED`, `RESOLVED`).
- **`system_logs`**: Immutable audit log of operator actions and telemetry reset events.

### Optional PostgreSQL Configuration:
```bash
# 1. Create database in PostgreSQL
createdb ids_database

# 2. Import Schema
psql -d ids_database -f schema.sql

# 3. Export Connection URL
export DATABASE_URL="postgresql://postgres:password@localhost:5432/ids_database"
```
*(If `DATABASE_URL` is omitted, the application runs automatically with local SQLite storage `data/ids_database.db`)*.

---

## 👥 Default SOC Credentials

| Username | Password | Role | Permissions |
|---|---|:---:|---|
| **`admin`** | `Admin@12345` | **ADMIN** | Full Access: Dashboard, Monitoring, Detections, Alerts, Reports, User Management, System Audit Logs, Telemetry Reset |
| **`analyst`** | `Analyst@12345` | **SECURITY_ANALYST** | Operations Access: Dashboard, Monitoring, Detections, Alerts (Acknowledge/Resolve), Reports |

---

## 🚀 Quickstart & Execution Guide

### 1. Environment Setup:
```bash
# Clone the repository
git clone https://github.com/hamzaaltayeb/IDS-Mon-AI.git
cd IDS-Mon-AI

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 2. Train AI Models on 11 Standard Flow Features:
```bash
python src/train_model.py
```
*Evaluates against the UNSW-NB15 benchmark testing set (113,894 samples) with 97.4% precision and saves trained `.joblib` artifacts to `models/`.*

### 3. Launch the SOC Web Dashboard:
```bash
python src/dashboard.py
```
Open your browser at **`http://localhost:5000`** to access the Security Operations Center.

### 4. Run Real-Time Live Traffic Monitoring (CLI):
```bash
# List discovered network interfaces on your host:
python src/realtime_monitor.py --list-interfaces

# Start Live Packet Sniffing on your active interface (e.g. wlp108s0, eth0):
sudo ./venv/bin/python src/realtime_monitor.py --mode live --interface wlp108s0 --flow-timeout 10 --debug-capture
```

---

## 🌐 Dual Monitoring Modes

AI-NSMS supports two operational modes:

### Mode 1: Live Network Monitoring Mode (Real Packet Capture)
- Captures real Ethernet/Wi-Fi frames directly from the selected physical interface.
- Builds bidirectional session flows using symmetric canonical 5-tuples.
- Features zero-rate safety protection for single-packet flows to eliminate division-by-epsilon false alarms.
- Feeds live traffic into the multi-tiered AI decision pipeline in real time.

### Mode 2: Simulation Mode (UNSW-NB15 Benchmark Samples)
- Useful for offline demonstrations, unit testing, and lab evaluation without network permissions.
```bash
python src/realtime_monitor.py --mode simulation -n 20 --interval 1.5
```

---

## 🧪 Authorized Lab Testing Procedures

```text
                           Local Lab Network (Switch / AP)
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
      [ Machine A: AI-NSMS ]   [ Machine B: Normal Client ]   [ Machine C: Security Tester ]
         Parrot OS / Linux         Windows / Linux / Android            Kali Linux
         IP: 10.251.32.71              IP: 10.251.32.80              IP: 192.168.1.200
                 │
                 ├── 1. Promiscuous Sniffing (wlp108s0 / eth0)
                 ├── 2. Flow Aggregation (11 Features)
                 ├── 3. Multi-Tiered AI Inference (Random Forest + Isolation Forest)
                 ├── 4. Threat Scoring & Forensic Indicators
                 └── 5. Database Persistence & Real-Time SOC Dashboard (Port 5000)
```

### 1. Normal Web & DNS Traffic:
Browse standard websites (Google, Wikipedia, GitHub) or run:
```bash
curl -s https://www.google.com > /dev/null
```
*Result:* Classified as **`NORMAL`** (Threat Score: `0/100`, Severity: `LOW`, 0 alerts).

### 2. Authorized Port Scan Test:
```bash
nmap -sS -p 20-1000 10.251.32.71
```
*Result:* Flagged as **`PORT_SCAN`** (Threat Score: `70/100`, Severity: `HIGH`, Alert created).

### 3. Authorized SSH Brute Force Test:
```bash
hydra -l admin -P wordlist.txt ssh://10.251.32.71
```
*Result:* Flagged as **`BRUTE_FORCE`** (Threat Score: `85/100`, Severity: `HIGH`, Alert created).

### 4. Controlled Volumetric Flood Test:
```bash
hping3 -S --flood -p 80 10.251.32.71
```
*Result:* Flagged as **`DDOS`** (Threat Score: `95/100`, Severity: `CRITICAL`, Alert created).

---

## 📁 Repository File Structure

```text
├── src/
│   ├── engine/                  # Core Real-Time AI & Packet Processing Engine
│   │   ├── interface_discovery.py# Dynamic Host Interface Enumeration & Metadata
│   │   ├── live_capture.py      # Real-Time AsyncSniffer & Dispatch Thread
│   │   ├── flow_collector.py    # Canonical Bidirectional FlowTable & Rate Engine
│   │   ├── feature_adapter.py   # 11-Feature Vector Formatter for Preprocessor
│   │   └── pipeline.py          # Multi-Tiered Decision Engine & Threat Scoring
│   ├── database/                # Database Storage & Models
│   │   ├── connection.py        # Connection Factory (PostgreSQL / SQLite)
│   │   ├── models.py            # User, NetworkFlow, Detection, Alert, SystemLog Models
│   │   └── seed.py              # Default Admin & Analyst Initializer
│   ├── auth/                    # RBAC & Security Layer
│   │   ├── security.py          # Session Auth & Role-Based Decorators (@admin_required)
│   │   └── audit.py             # System Audit Logger
│   ├── routes/                  # Modular Flask Blueprints (RESTful APIs & UI views)
│   ├── data/                    # Real UNSW-NB15 Benchmark Dataset CSV Files
│   ├── models/                  # Trained AI Model Artifacts (.joblib)
│   ├── preprocessing.py         # StandardScaler & LabelEncoder Module
│   ├── anomaly_model.py         # Isolation Forest (Unsupervised Anomaly Model)
│   ├── classifier_model.py      # Random Forest Multi-Class Classifier
│   ├── realtime_monitor.py      # CLI Monitoring Entry Point (Live & Simulation)
│   └── dashboard.py             # Main Flask SOC Application Entry Point
├── templates/                   # High-Tech Cyber SOC Web Views (Jinja2)
├── static/                      # CSS Styling & JavaScript (Chart.js dynamic charts)
├── schema.sql                   # Relational Database Schema DDL
├── requirements.txt             # Project Python Dependencies
└── README.md                    # Project Documentation
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
