import os
import pandas as pd
from datetime import datetime

class ReportGenerator:
    """
    Generates security reports from the alerts log file.
    """
    def __init__(self, log_file="logs/alerts.log", report_dir="reports"):
        self.log_file = log_file
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)

    def parse_logs(self):
        """
        Parses the alerts log file into a list of dictionaries.
        """
        alerts = []
        if not os.path.exists(self.log_file):
            return alerts
            
        with open(self.log_file, "r") as f:
            for line in f:
                try:
                    # Format: 2026-02-26 13:06:53,328 | WARNING | Attack | IP | Severity | Score
                    parts = line.strip().split(" | ")
                    if len(parts) == 6:  # Time | Level | Attack | IP | Severity | Score
                        timestamp_str = parts[0].split(",")[0]
                        alerts.append({
                            'timestamp': timestamp_str,
                            'attack': parts[2],
                            'ip': parts[3],
                            'severity': parts[4],
                            'score': int(parts[5])
                        })
                except Exception as e:
                    print(f"Error parsing log line: {e}")
        return alerts

    def generate_markdown_report(self):
        """
        Creates a markdown report with statistics.
        """
        alerts = self.parse_logs()
        if not alerts:
            print("No alerts found to generate report.")
            return None

        df = pd.DataFrame(alerts)
        report_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_file = os.path.join(self.report_dir, f"security_report_{report_time}.md")

        with open(report_file, "w") as f:
            f.write("# Security Audit Report\n\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Summary Statistics\n")
            f.write(f"- **Total Alerts**: {len(df)}\n")
            f.write(f"- **Unique IPs Flagged**: {df['ip'].nunique()}\n")
            f.write(f"- **Critical Attacks**: {len(df[df['severity'] == 'Critical'])}\n\n")

            f.write("## Attacks by Type\n")
            attack_counts = df['attack'].value_counts()
            f.write("| Attack Type | Count |\n")
            f.write("|-------------|-------|\n")
            for attack, count in attack_counts.items():
                f.write(f"| {attack} | {count} |\n")
            f.write("\n")

            f.write("## Detailed Alerts (Last 20)\n")
            f.write("| Timestamp | IP Address | Attack | Severity | Score |\n")
            f.write("|-----------|------------|--------|----------|-------|\n")
            for _, row in df.tail(20).iterrows():
                f.write(f"| {row['timestamp']} | {row['ip']} | {row['attack']} | {row['severity']} | {row['score']} |\n")

        print(f"Report generated: {report_file}")
        return report_file

if __name__ == "__main__":
    gen = ReportGenerator()
    gen.generate_markdown_report()
