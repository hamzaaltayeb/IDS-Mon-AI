/**
 * ==============================================================================
 * AI-NSMS: Audio Alerting Engine (Web Audio API Native Synthesis)
 * Enterprise-Grade, Zero-Dependency Audio Notification & Cooldown Controller
 * ==============================================================================
 */

class AudioAlertManager {
    constructor() {
        // Audio Cooldown Settings (in milliseconds) - Configurable constant
        this.COOLDOWN_MS = 8000; // 8 seconds cooldown per severity level to prevent sound flooding
        
        // Cooldown trackers: timestamp of last played sound per severity
        this.lastPlayedTimes = {
            'LOW': 0,
            'MEDIUM': 0,
            'HIGH': 0,
            'CRITICAL': 0
        };

        // Track seen alert IDs to prevent re-triggering audio on existing alerts
        this.seenAlertIds = new Set();

        // Mute state: persisted across sessions via localStorage
        const storedMute = localStorage.getItem('ai_nsms_audio_muted');
        this.isMuted = (storedMute === 'true');

        // Web Audio Context (lazy initialization on user gesture)
        this.audioCtx = null;

        // Initialize UI bindings after DOM loads
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.initUI());
        } else {
            this.initUI();
        }
    }

    /**
     * Initializes or resumes the Web Audio Context (browser autoplay compliance).
     */
    getAudioContext() {
        if (!this.audioCtx) {
            const AudioContextClass = window.AudioContext || window.webkitAudioContext;
            if (AudioContextClass) {
                this.audioCtx = new AudioContextClass();
            }
        }
        if (this.audioCtx && this.audioCtx.state === 'suspended') {
            this.audioCtx.resume();
        }
        return this.audioCtx;
    }

    /**
     * Toggles Mute / Unmute state.
     */
    toggleMute() {
        this.isMuted = !this.isMuted;
        localStorage.setItem('ai_nsms_audio_muted', this.isMuted ? 'true' : 'false');
        this.updateUI();
        
        if (!this.isMuted) {
            // Play a short feedback beep to confirm unmute
            this.playTone(587.33, 0.1, 'sine', 0.15); // D5 note
        }
        
        return this.isMuted;
    }

    /**
     * Sets explicit mute state.
     */
    setMute(muteState) {
        this.isMuted = Boolean(muteState);
        localStorage.setItem('ai_nsms_audio_muted', this.isMuted ? 'true' : 'false');
        this.updateUI();
    }

    /**
     * Updates all Mute/Unmute buttons and status badges in the DOM.
     */
    updateUI() {
        const statusButtons = document.querySelectorAll('.btn-audio-toggle');
        const statusBadges = document.querySelectorAll('.audio-status-indicator');

        statusButtons.forEach(btn => {
            if (this.isMuted) {
                btn.innerHTML = '<i class="fas fa-volume-xmark" style="color: var(--sev-critical);"></i> <span>Audio: OFF</span>';
                btn.className = 'btn btn-outline-danger btn-sm btn-audio-toggle';
                btn.title = 'Audio Alerts are MUTED. Click to Unmute.';
            } else {
                btn.innerHTML = '<i class="fas fa-volume-high" style="color: var(--sev-low);"></i> <span>Audio: ON</span>';
                btn.className = 'btn btn-outline-success btn-sm btn-audio-toggle';
                btn.title = 'Audio Alerts are ACTIVE. Click to Mute.';
            }
        });

        statusBadges.forEach(badge => {
            if (this.isMuted) {
                badge.innerHTML = '<i class="fas fa-volume-xmark"></i> 🔇 Audio Alerts: OFF';
                badge.className = 'badge-sev badge-medium audio-status-indicator';
                badge.style.color = '#ef4444';
            } else {
                badge.innerHTML = '<i class="fas fa-volume-high"></i> 🔊 Audio Alerts: ON';
                badge.className = 'badge-sev badge-low audio-status-indicator';
                badge.style.color = '#10b981';
            }
        });
    }

    /**
     * Sets up UI hooks and listeners.
     */
    initUI() {
        this.updateUI();

        // Enable audio context on any user click anywhere on page
        const unlockAudio = () => {
            this.getAudioContext();
            document.removeEventListener('click', unlockAudio);
            document.removeEventListener('keydown', unlockAudio);
        };
        document.addEventListener('click', unlockAudio, { once: true });
        document.addEventListener('keydown', unlockAudio, { once: true });
    }

    /**
     * Helper: Synthesizes a clean audio tone using Web Audio API.
     */
    playTone(frequency, durationSec, type = 'sine', gainLevel = 0.2, startTimeOffset = 0) {
        if (this.isMuted) return;
        const ctx = this.getAudioContext();
        if (!ctx) return;

        try {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();

            osc.type = type;
            osc.frequency.setValueAtTime(frequency, ctx.currentTime + startTimeOffset);

            // Envelope: Attack and Exponential Decay
            const startT = ctx.currentTime + startTimeOffset;
            gain.gain.setValueAtTime(0.001, startT);
            gain.gain.exponentialRampToValueAtTime(gainLevel, startT + 0.02);
            gain.gain.exponentialRampToValueAtTime(0.0001, startT + durationSec);

            osc.connect(gain);
            gain.connect(ctx.destination);

            osc.start(startT);
            osc.stop(startT + durationSec + 0.05);
        } catch (e) {
            console.warn("[AudioAlertManager] Error playing tone:", e);
        }
    }

    /**
     * Synthesizes Level 2: WARNING / SUSPICIOUS Sound (MEDIUM Severity / UNKNOWN).
     * Short dual chime (Soft sine wave).
     */
    playWarningSound() {
        if (this.isMuted) return;
        this.playTone(523.25, 0.12, 'sine', 0.20, 0.00); // C5
        this.playTone(659.25, 0.16, 'sine', 0.25, 0.10); // E5
    }

    /**
     * Synthesizes Level 3: HIGH / ATTACK Sound (HIGH Severity - Port Scan / Brute Force).
     * Pulsing tactical alert tone.
     */
    playAttackSound() {
        if (this.isMuted) return;
        const ctx = this.getAudioContext();
        if (!ctx) return;

        try {
            // Pulse 1
            this.playTone(740.0, 0.14, 'triangle', 0.30, 0.00);
            this.playTone(554.37, 0.16, 'triangle', 0.30, 0.12);

            // Pulse 2
            this.playTone(740.0, 0.14, 'triangle', 0.30, 0.30);
            this.playTone(554.37, 0.20, 'triangle', 0.30, 0.42);
        } catch (e) {
            console.warn("[AudioAlertManager] Error playing attack sound:", e);
        }
    }

    /**
     * Synthesizes Level 4: CRITICAL ATTACK Sound (CRITICAL Severity - DDoS Floods).
     * High-urgency klaxon/siren multi-tone alarm.
     */
    playCriticalSound() {
        if (this.isMuted) return;
        const ctx = this.getAudioContext();
        if (!ctx) return;

        try {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();

            osc.type = 'sawtooth';
            const now = ctx.currentTime;

            // Frequency modulation sweep: 880Hz -> 1174Hz -> 880Hz -> 1174Hz
            osc.frequency.setValueAtTime(880, now);
            osc.frequency.exponentialRampToValueAtTime(1174.66, now + 0.15);
            osc.frequency.exponentialRampToValueAtTime(880, now + 0.30);
            osc.frequency.exponentialRampToValueAtTime(1174.66, now + 0.45);
            osc.frequency.exponentialRampToValueAtTime(700, now + 0.60);

            gain.gain.setValueAtTime(0.001, now);
            gain.gain.exponentialRampToValueAtTime(0.35, now + 0.04);
            gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.65);

            osc.connect(gain);
            gain.connect(ctx.destination);

            osc.start(now);
            osc.stop(now + 0.70);
        } catch (e) {
            console.warn("[AudioAlertManager] Error playing critical sound:", e);
        }
    }

    /**
     * Evaluates incoming alert/detection and triggers the appropriate sound
     * subject to Mute state and Severity-based Cooldown deduplication.
     * 
     * @param {Object} alertObj - Object containing { id, severity, attack_type, threat_score }
     */
    trigger(alertObj) {
        if (!alertObj) return false;

        const rawSev = (alertObj.severity || 'LOW').toUpperCase();
        const attackType = (alertObj.attack_type || alertObj.attack || '').toUpperCase();
        const alertId = alertObj.id || `${alertObj.source_ip}_${alertObj.destination_ip}_${attackType}_${Date.now()}`;

        // 1. Check if alert is Normal / Low severity -> No sound
        if (rawSev === 'LOW' || attackType === 'NORMAL' || rawSev === 'NORMAL') {
            return false;
        }

        // 2. Check if this exact alert ID was already processed for audio
        if (alertObj.id && this.seenAlertIds.has(alertObj.id)) {
            return false;
        }
        if (alertObj.id) {
            this.seenAlertIds.add(alertObj.id);
            // Limit memory of seenAlertIds
            if (this.seenAlertIds.size > 2000) {
                const firstItem = this.seenAlertIds.values().next().value;
                this.seenAlertIds.delete(firstItem);
            }
        }

        // 3. Check Audio Cooldown for this severity level
        const now = Date.now();
        const lastPlayed = this.lastPlayedTimes[rawSev] || 0;
        const timeSinceLast = now - lastPlayed;

        if (timeSinceLast < this.COOLDOWN_MS) {
            console.log(`[AudioAlert] Audio Cooldown ACTIVE for ${rawSev} (${Math.round((this.COOLDOWN_MS - timeSinceLast)/1000)}s remaining). Sound suppressed.`);
            return false; // Sound suppressed by cooldown
        }

        // 4. Update cooldown timestamp
        this.lastPlayedTimes[rawSev] = now;

        // 5. Dispatch sound according to Severity Level
        if (this.isMuted) {
            console.log(`[AudioAlert] ${rawSev} Alert registered, but Audio is MUTED.`);
            return false;
        }

        console.log(`[AudioAlert] 🔔 Playing Audio Alert for [${rawSev}] Threat: ${attackType}`);
        switch (rawSev) {
            case 'CRITICAL':
                this.playCriticalSound();
                break;
            case 'HIGH':
                this.playAttackSound();
                break;
            case 'MEDIUM':
                this.playWarningSound();
                break;
            default:
                break;
        }

        return true;
    }

    /**
     * Batch evaluates a list of active alerts (e.g. from polling endpoint /api/alerts).
     */
    processAlertsList(alerts) {
        if (!Array.isArray(alerts) || alerts.length === 0) return;

        // Process newest alerts first
        const newAlerts = alerts.filter(a => a.status === 'NEW' || !a.status);
        if (newAlerts.length > 0) {
            // Find the highest severity among new alerts
            const severityRank = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
            newAlerts.sort((a, b) => {
                const rankA = severityRank[(a.severity || 'LOW').toUpperCase()] || 0;
                const rankB = severityRank[(b.severity || 'LOW').toUpperCase()] || 0;
                return rankB - rankA;
            });

            // Trigger sound for the most severe new alert
            this.trigger(newAlerts[0]);
        }
    }
}

// Global Singleton Instance
window.audioAlerts = new AudioAlertManager();
