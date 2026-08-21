from flask import Flask, render_template, jsonify
import os

app = Flask(__name__, template_folder='../templates')

LOG_FILE = "logs/alerts.log"

def parse_alerts():
    alerts = []
    if not os.path.exists(LOG_FILE):
        return alerts
        
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
        # Get last 50 alerts
        for line in reversed(lines):
            try:
                parts = line.strip().split(" | ")
                if len(parts) >= 3:
                    timestamp = parts[0].split(",")[0]
                    data = parts[2].split(" | ")
                    if len(data) == 4:
                        alerts.append({
                            'timestamp': timestamp,
                            'attack': data[0],
                            'ip': data[1],
                            'severity': data[2],
                            'score': data[3]
                        })
                if len(alerts) >= 50:
                    break
            except:
                continue
    return alerts

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    alerts = parse_alerts()
    return jsonify(alerts)

@app.route('/api/stats')
def get_stats():
    alerts = parse_alerts()
    stats = {
        'total': len(alerts),
        'critical': len([a for a in alerts if a['severity'] == 'Critical']),
        'high': len([a for a in alerts if a['severity'] == 'High']),
        'medium': len([a for a in alerts if a['severity'] == 'Medium'])
    }
    return jsonify(stats)

if __name__ == '__main__':
    print("Starting Security Dashboard at http://localhost:5000")
    app.run(debug=True, port=5000)
