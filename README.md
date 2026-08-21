# Intelligent Network Security Monitoring System using AI 🛡️🤖

A comprehensive network security monitoring system that leverages Machine Learning (Isolation Forest & Random Forest) to detect anomalies and classify cyber attacks in real-time.

## 🚀 Features

- **Real-Time Traffic Analysis**: Processes network data to identify suspicious patterns live.
- **AI-Driven Detection**: 
  - **Isolation Forest**: For unsupervised anomaly detection (finding unknown threats).
  - **Random Forest**: For supervised attack classification (DDoS, Port Scanning, Brute Force).
- **Interactive Dashboard**: A web-based UI built with Flask to visualize threats and statistics.
- **Automated Reporting**: Generates detailed security audit reports in Markdown.
- **Structured Alerting**: Calculates threat scores (0-100) and severity levels.

---

## 📁 Repository Structure

```text
├── src/                    # Source code
│   ├── data_collector.py     # Network traffic ingestion
│   ├── feature_extractor.py  # Feature engineering
│   ├── preprocessing.py      # Data cleaning & Scaling
│   ├── anomaly_model.py      # Isolation Forest implementation
│   ├── classifier_model.py   # Random Forest implementation
│   ├── train_model.py        # Model training pipeline
│   ├── realtime_monitor.py   # Main monitoring engine
│   ├── alerts.py             # Structured alerting system
│   ├── dashboard.py          # Flask web app
│   └── reports_generator.py  # Report generation logic
├── templates/              # Dashboard HTML templates
├── data/                   # Synthetic and real dataset storage (ignored)
├── models/                 # Trained model storage (ignored)
├── logs/                   # Security alert logs (ignored)
├── reports/                # Generated security reports (ignored)
├── requirements.txt        # Project dependencies
└── README.md               # You are here
```

---

## 🛠️ Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/hamzaaltieb56-alt/Intelligent-Network-Security-Monitoring-System-using-AI.git
   cd Intelligent-Network-Security-Monitoring-System-using-AI
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Train the AI Models**:
   ```bash
   python src/train_model.py
   ```

4. **Run the Monitor & Dashboard**:
   - In terminal 1 (Monitor):
     ```bash
     python src/realtime_monitor.py
     ```
   - In terminal 2 (Dashboard):
     ```bash
     python src/dashboard.py
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
# IDS-Mon-AI
