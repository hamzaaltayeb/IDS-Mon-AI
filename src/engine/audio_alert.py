import time
import sys
import threading

class AudioAlertController:
    """
    Modular Audio Alerting Engine for Backend & CLI Monitoring.
    Maintains severity-based audio cooldown and mute state with zero external dependencies.
    """
    _instance = None
    DEFAULT_COOLDOWN_SECONDS = 8.0  # Configurable cooldown in seconds

    def __init__(self, cooldown_seconds=None):
        self.cooldown_seconds = float(cooldown_seconds or self.DEFAULT_COOLDOWN_SECONDS)
        self.is_muted = False
        self.last_played_times = {
            'LOW': 0.0,
            'MEDIUM': 0.0,
            'HIGH': 0.0,
            'CRITICAL': 0.0
        }
        self.lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def set_muted(self, muted: bool):
        with self.lock:
            self.is_muted = bool(muted)

    def toggle_mute(self) -> bool:
        with self.lock:
            self.is_muted = not self.is_muted
            return self.is_muted

    def can_play_sound(self, severity: str) -> bool:
        sev = str(severity).upper()
        if self.is_muted or sev in ['LOW', 'NORMAL']:
            return False

        with self.lock:
            now = time.time()
            last_time = self.last_played_times.get(sev, 0.0)
            if (now - last_time) >= self.cooldown_seconds:
                self.last_played_times[sev] = now
                return True
            return False

    def trigger_alert(self, attack_type: str, severity: str, threat_score: int = 0) -> bool:
        """
        Evaluates an alert and emits a terminal bell/notification if cooldown allows.
        """
        sev = str(severity).upper()
        atk = str(attack_type).upper()

        if not self.can_play_sound(sev):
            return False

        try:
            # Emit standard terminal bell character
            if sev == 'CRITICAL':
                # Double rapid chime
                sys.stdout.write('\a\a')
                sys.stdout.flush()
            elif sev in ['HIGH', 'MEDIUM']:
                # Single chime
                sys.stdout.write('\a')
                sys.stdout.flush()
            return True
        except Exception:
            return False

# Global Singleton
audio_alert_controller = AudioAlertController.get_instance()
