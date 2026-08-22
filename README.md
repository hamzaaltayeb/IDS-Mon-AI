# 🛡️ Intelligent Network Security Monitoring System using AI (AI-NSMS)

An enterprise-grade, real-time Security Operations Center (SOC) platform powered by Artificial Intelligence and Machine Learning for continuous network flow analysis, anomaly detection, and automated threat classification.

---

## 🎯 Target Attack Classes & Scope
1. **DDoS Attack** (`Critical - Score: 95/100`) - Volumetric floods and high packet rate saturation.
2. **Port Scanning** (`High - Score: 70/100`) - Reconnaissance port sweeps and service probes.
3. **Brute Force** (`High - Score: 85/100`) - Repeated authentication cracking on SSH/FTP/RDP ports.
4. **Normal Traffic** (`Low - Score: 0/100`) - Clean baseline network communications.
5. **Unknown Threat** (`Medium - Score: 50/100`) - Statistical anomalies flagged by Isolation Forest.

---

## 📊 Extracted 11 Network Flow Features
The AI detection engine analyzes 11 standard flow metrics:
1. `Protocol` (Transport protocol e.g. TCP, UDP)
2. `Destination Port` (Target service port)
3. `Total Flow Size` (Total bytes in session)
4. `Average Packet Size` (Mean payload size)
5. `Standard Deviation of Packet Size`
6. `Packet Count` (Total packets in flow)
7. `Flow Duration` (Active session time in seconds)
8. `Average Inter-Arrival Time`
9. `Maximum Inter-Arrival Time`
10. `Packets Per Second (Rate)`
11. `Bytes Per Second (Throughput)`

---

## 🗄️ Database Architecture & PostgreSQL Support
The system provides a relational schema in `schema.sql` with 5 operational tables:
- `users`: Authentication, RBAC (`ADMIN`, `SECURITY_ANALYST`), password hashing, last login.
- `network_flows`: Extracted 11-feature flow records (raw packets are never stored).
- `detections`: AI prediction results, confidence, threat score, severity, and forensic reasoning indicators.
- `alerts`: Security incident queue (`NEW`, `ACKNOWLEDGED`, `RESOLVED`).
- `system_logs`: Immutable audit trail of operator and administrative activities.

### Setting up PostgreSQL (Optional / Production):
```bash
# 1. Create database in PostgreSQL
createdb ids_database

# 2. Import Schema
psql -d ids_database -f schema.sql

# 3. Export Environment Variable
export DATABASE_URL="postgresql://postgres:password@localhost:5432/ids_database"
```
*(If `DATABASE_URL` is omitted, the application runs automatically with local SQLite storage `data/ids_database.db`)*.

---

## 👥 Default Testing Accounts
| Username | Password | Role | Permissions |
|---|---|:---:|---|
| `admin` | `Admin@12345` | **ADMIN** | Full Access: Dashboard, Monitoring, Detections, Alerts, Reports, User Management, System Audit Logs |
| `analyst` | `Analyst@12345` | **SECURITY_ANALYST** | Operations Access: Dashboard, Monitoring, Detections, Alerts (Acknowledge/Resolve), Reports. (Forbidden from User Management) |

---

## 🚀 Quickstart & Execution

### 1. Activate Environment & Install Dependencies:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Train AI Models (UNSW-NB15 Benchmark):
```bash
python src/train_model.py
```

### 3. Run SOC Dashboard & Web Application:
```bash
python src/dashboard.py
```
Open your browser at **`http://localhost:5000`** to access the SOC Portal.

### 4. Run Live Network Monitoring Stream:
```bash
python src/realtime_monitor.py
```
*(Runs continuously; press Ctrl+C to stop, or use `-n 20` for 20 cycles)*

## 🌐 Dual Monitoring Modes (Live Packet Capture vs. Simulation)

AI-NSMS supports two distinct operational modes:

### 1. Mode 1: Simulation Mode (UNSW-NB15 Benchmark Samples)
- Useful for testing, offline verification, and development.
- Streams flow records sampled from the real `UNSW-NB15` benchmark testing dataset through the downstream detection pipeline.
```bash
# Run simulation mode via CLI
python src/realtime_monitor.py --mode simulation -n 10 --interval 2.0
```

### 2. Mode 2: Live Network Monitoring Mode (Real Packet Capture)
- Captures actual network packets from a physical or virtual network interface (`eth0`, `wlan0`, `enp3s0`, `lo`, etc.).
- Aggregates packets into 5-tuple flow sessions in a thread-safe `FlowTable`.
- Finalizes flows upon inactivity timeout (`--flow-timeout 10`) or TCP termination (`FIN`/`RST`).
- Calculates the 11 flow features, normalizes them via `FeatureCompatibilityAdapter`, evaluates them with the dual AI models, and saves results into PostgreSQL.
```bash
# Run live packet capture on selected network interface (requires root/sudo for promiscuous capture)
sudo ./venv/bin/python src/realtime_monitor.py --mode live --interface wlan0 --filter "ip" --flow-timeout 10
```

---

## 🧪 Local Lab Testing Topology

```text
                           Local Lab Network (Switch / AP)
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
      [ Machine A: AI-NSMS ]   [ Machine B: Client ]   [ Machine C: Security Tester ]
         Parrot OS / Linux         Windows / Linux             Kali Linux
         IP: 192.168.1.50          IP: 192.168.1.10          IP: 192.168.1.200
                 │
                 ├── 1. Packet Sniffing (wlan0 / eth0)
                 ├── 2. Flow Aggregation (11 Features)
                 ├── 3. AI Inference (Isolation + Random Forest)
                 ├── 4. Threat Scoring & Forensic Indicators
                 └── 5. PostgreSQL Persistence & SOC Dashboard (port 5000)
```

### Safe Testing Scenarios:
1. **Normal Web Browsing (Machine B $\rightarrow$ Web Server):** Generates clean TCP/HTTPS flows (classified as `NORMAL`, Threat Score: `0`).
2. **Authorized Port Scanning (Machine C $\rightarrow$ Machine A):**
   ```bash
   nmap -sS -p 20-1000 192.168.1.50
   ```
   *(Classified as `PORT_SCAN`, Threat Score: `70/100`, Severity: `HIGH`)*
3. **Authorized SSH Brute Force (Machine C $\rightarrow$ Machine A):**
   ```bash
   hydra -l admin -P wordlist.txt ssh://192.168.1.50
   ```
   *(Classified as `BRUTE_FORCE`, Threat Score: `85/100`, Severity: `HIGH`)*
4. **Controlled Volumetric Flood / DDoS Test:**
   ```bash
   hping3 -S --flood -p 80 192.168.1.50
   ```
   *(Classified as `DDOS`, Threat Score: `95/100`, Severity: `CRITICAL`)*

---

## 🎓 Academic Distinction & Limitations

> [!IMPORTANT]
> **Academic Note on Dataset vs. Live Traffic:**
> 1. **UNSW-NB15** is an offline academic benchmark dataset used strictly for model training, hyperparameter tuning, and baseline evaluation.
> 2. **Live Mode** captures raw network frames from the host interface and converts them dynamically into the 11 standard flow features.
> 3. While the `FeatureCompatibilityAdapter` maps operational flow statistics to the feature space of the preprocessor, real-world deployment accuracy may vary due to network topology variations, payload encryption (TLS), and environmental noise.

---

## 📁 Repository Structure

```text
├── src/
│   ├── engine/                  # Core Real-Time AI & Packet Processing Engine
│   │   ├── live_capture.py      # Real-time packet sniffer (Scapy AsyncSniffer)
│   │   ├── flow_collector.py    # 5-tuple flow aggregation & 11-feature calculator
│   │   ├── feature_adapter.py   # Feature compatibility mapper
│   │   └── pipeline.py          # Centralized AI inference & DB persistence
│   ├── database/                # Database layer
│   │   ├── connection.py        # Connection factory (PostgreSQL / SQLite)
│   │   ├── models.py            # SQLAlchemy/ORM Data Models (User, Flow, Detection, Alert, Log)
│   │   └── seed.py              # Initial admin/analyst seeding
│   ├── auth/                    # Security & Authentication
│   │   ├── security.py          # Password hashing, RBAC decorators (@admin_required)
│   │   └── audit.py             # System audit logger
│   ├── routes/                  # Modular Flask Blueprints (RESTful APIs & UI views)
│   ├── data/                    # Real UNSW-NB15 Benchmark dataset files
│   ├── models/                  # Trained AI models (.joblib)
│   ├── preprocessing.py         # StandardScaler & LabelEncoder
│   ├── anomaly_model.py         # Isolation Forest (Unsupervised)
│   ├── classifier_model.py      # Random Forest Classifier (Supervised)
│   ├── realtime_monitor.py      # Dual-mode monitor CLI (Simulation & Live)
│   └── dashboard.py             # SOC Dashboard application entry point
├── templates/                   # High-tech Dark Cyber SOC templates (Jinja2)
├── static/                      # CSS & JS (Chart.js dynamic charts)
├── schema.sql                   # PostgreSQL schema DDL script
├── requirements.txt             # Project dependencies
└── README.md                    # Project documentation
```

---

## 📊 Dashboard Preview

Navigate to `http://localhost:5000` to see the live security dashboard.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
# AI-NSMS
