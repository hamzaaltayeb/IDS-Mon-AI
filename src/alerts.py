import logging
import datetime
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOG_FILE = os.path.join(BASE_DIR, "logs", "alerts.log")

class AlertSystem:
    """
    Module for generating and logging security alerts.
    Calculates threat scores and saves alerts to logs/alerts.log.
    """
    def __init__(self, log_file=None):
        self.log_file = log_file or DEFAULT_LOG_FILE
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        self.logger = logging.getLogger("AlertSystem")
        self.logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers
        if not self.logger.handlers:
            handler = logging.FileHandler(self.log_file, encoding='utf-8')
            # Structured format: Time | Level | Attack | IP | Severity | Score
            formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def calculate_score(self, attack_type, confidence=1.0):
        """
        Calculates a threat score (0-100) and severity level based on attack type.
        Target scope: Normal, DDoS, Brute Force, Port Scan, and Unknown.
        """
        scores = {
            'Normal': (0, 'Low'),
            'DDoS': (95, 'Critical'),
            'Brute Force': (85, 'High'),
            'Port Scan': (70, 'High'),
            'Unknown': (50, 'Medium')
        }
        
        base_score, severity = scores.get(attack_type, (50, 'Medium'))
        final_score = min(100, max(0, int(base_score * confidence)))
        
        return final_score, severity


    def trigger_alert(self, ip_address, attack_type, confidence=1.0):
        """
        Prints an alert message and logs it to the file.
        """
        if attack_type == 'Normal':
            return None

        score, severity = self.calculate_score(attack_type, confidence)
        
        # Structured message for easier parsing
        log_msg = f"{attack_type} | {ip_address} | {severity} | {score}"
        alert_msg = f"ALERT: Suspicious activity detected from IP {ip_address} | Attack: {attack_type} | Severity: {severity} | Score: {score}/100"
        
        print(f"\033[91m{alert_msg}\033[0m") # Red text for console
        self.logger.warning(log_msg)

        # Trigger terminal audio notification if enabled
        try:
            from engine.audio_alert import audio_alert_controller
            audio_alert_controller.trigger_alert(attack_type, severity, score)
        except Exception:
            pass
        
        return {
            'timestamp': datetime.datetime.now().isoformat(),
            'ip': ip_address,
            'attack': attack_type,
            'severity': severity,
            'score': score
        }

if __name__ == "__main__":
    alert_sys = AlertSystem()
    alert_sys.trigger_alert("192.168.1.100", "DDoS", 0.98)
    alert_sys.trigger_alert("10.0.0.5", "Port Scan", 0.85)

