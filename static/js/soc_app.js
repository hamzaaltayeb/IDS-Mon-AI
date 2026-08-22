// SOC Operational Dashboard & Real-Time Monitoring Utilities (AI-NSMS)

document.addEventListener('DOMContentLoaded', () => {
    // Auto-dismiss flashes
    setTimeout(() => {
        const flashes = document.querySelectorAll('.flash-msg');
        flashes.forEach(f => {
            f.style.opacity = '0';
            setTimeout(() => f.remove(), 400);
        });
    }, 5000);
});

// Helper: Acknowledge / Resolve Alert
async function updateAlertStatus(alertId, newStatus) {
    try {
        const res = await fetch(`/api/alerts/${alertId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus })
        });
        const data = await res.json();
        if (data.success) {
            window.location.reload();
        } else {
            alert(data.error || 'Failed to update alert');
        }
    } catch (e) {
        console.error("Error updating alert:", e);
    }
}

// Reset / Purge Telemetry Data and Zero All Counters
async function resetMonitoringData() {
    const confirmed = confirm("⚠️ Are you sure you want to PURGE all network flows, detections, and alerts, and reset all live stream counters to 0?");
    if (!confirmed) return;

    try {
        const res = await fetch('/api/monitoring/reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await res.json();
        if (data.success) {
            updateLiveTelemetryUI(data.status);
            if (typeof loadFlows === 'function') loadFlows();
            if (typeof loadDashboardData === 'function') loadDashboardData();
            showToastMessage("✅ Telemetry database and all stream counters have been reset successfully.", "success");
        } else {
            alert(data.error || 'Failed to reset telemetry data');
        }
    } catch (e) {
        console.error("Error resetting telemetry:", e);
        alert("Error connecting to server for reset operation.");
    }
}

function showToastMessage(msg, type = "info") {
    let toast = document.getElementById('soc-global-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'soc-global-toast';
        toast.style.position = 'fixed';
        toast.style.bottom = '20px';
        toast.style.right = '20px';
        toast.style.zIndex = '9999';
        toast.style.padding = '12px 20px';
        toast.style.borderRadius = '8px';
        toast.style.boxShadow = '0 8px 24px rgba(0,0,0,0.5)';
        toast.style.fontWeight = '600';
        toast.style.fontSize = '0.9rem';
        toast.style.transition = 'opacity 0.3s ease';
        document.body.appendChild(toast);
    }
    toast.style.background = (type === 'success') ? '#00e676' : (type === 'error' ? '#ff1744' : '#00e5ff');
    toast.style.color = '#0b0f19';
    toast.innerText = msg;
    toast.style.opacity = '1';
    setTimeout(() => {
        toast.style.opacity = '0';
    }, 4000);
}

// Simulation Mode: Ingest Batch from UNSW-NB15 Benchmark
async function simulateLiveFlows(batchSize = 5) {
    const btn = document.getElementById('btn-simulate');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Ingesting...';
    }
    try {
        const res = await fetch('/api/monitoring/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ batch_size: batchSize })
        });
        const data = await res.json();
        if (data.success) {
            if (typeof loadFlows === 'function') loadFlows();
            showToastMessage(`✨ Ingested ${data.count} benchmark flows successfully.`, 'info');
        } else {
            alert(data.error || 'Simulation error');
        }
    } catch (e) {
        console.error("Simulation error:", e);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-bolt"></i> Ingest 5 Benchmark Flows';
        }
    }
}

// Live Mode: Start Real-Time Packet Sniffing
async function startLiveCapture() {
    const ifaceSelect = document.getElementById('live-interface-select');
    const filterInput = document.getElementById('live-filter-input');
    const timeoutInput = document.getElementById('live-timeout-input');
    const debugCheckbox = document.getElementById('live-debug-checkbox');
    const btnStart = document.getElementById('btn-start-live');

    const iface = ifaceSelect ? ifaceSelect.value : null;
    const filter = filterInput ? filterInput.value.trim() : 'ip';
    const timeout = timeoutInput ? parseFloat(timeoutInput.value) : 10.0;
    const debug = debugCheckbox ? debugCheckbox.checked : false;

    if (btnStart) {
        btnStart.disabled = true;
        btnStart.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';
    }

    try {
        const res = await fetch('/api/monitoring/live/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: iface, filter: filter, flow_timeout: timeout, debug_capture: debug })
        });
        const data = await res.json();
        if (data.success) {
            updateLiveTelemetryUI(data.status);
            showToastMessage(`🚀 ${data.message}`, 'success');
        } else {
            alert(data.message || data.error || 'Could not start live capture.');
        }
    } catch (e) {
        console.error("Error starting live capture:", e);
        alert("Error starting live capture. Check backend privileges.");
    } finally {
        if (btnStart) {
            btnStart.disabled = false;
            btnStart.innerHTML = '<i class="fas fa-play"></i> Start Live Capture';
        }
    }
}

// Live Mode: Stop Real-Time Packet Sniffing
async function stopLiveCapture() {
    const btnStop = document.getElementById('btn-stop-live');
    if (btnStop) {
        btnStop.disabled = true;
        btnStop.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Stopping...';
    }

    try {
        const res = await fetch('/api/monitoring/live/stop', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await res.json();
        if (data.status) {
            updateLiveTelemetryUI(data.status);
            showToastMessage('⏹️ Live packet capture stopped.', 'info');
        }
    } catch (e) {
        console.error("Error stopping live capture:", e);
    } finally {
        if (btnStop) {
            btnStop.disabled = false;
            btnStop.innerHTML = '<i class="fas fa-stop"></i> Stop Live Capture';
        }
    }
}

// Live Mode: Poll Telemetry Status
async function pollLiveTelemetry() {
    try {
        const res = await fetch('/api/monitoring/live/status');
        const status = await res.json();
        updateLiveTelemetryUI(status);
    } catch (e) {
        console.error("Telemetry poll error:", e);
    }
}

function updateLiveTelemetryUI(status) {
    if (!status) return;

    const badge = document.getElementById('live-status-badge');
    const packetsEl = document.getElementById('live-packets-count');
    const activeFlowsEl = document.getElementById('live-active-flows');
    const finalizedFlowsEl = document.getElementById('live-finalized-flows');
    const analyzedFlowsEl = document.getElementById('live-analyzed-flows');
    const detectionsEl = document.getElementById('live-detections-count');
    const alertsEl = document.getElementById('live-alerts-count');
    const uptimeEl = document.getElementById('live-uptime');
    const errorBox = document.getElementById('live-error-box');
    const loopbackWarningBox = document.getElementById('live-loopback-warning');

    if (badge) {
        if (status.is_running) {
            badge.className = 'badge-sev badge-low';
            badge.innerHTML = '<span class="pulse-dot" style="display:inline-block; margin-right:4px;"></span> CAPTURING (ACTIVE)';
        } else {
            badge.className = 'badge-sev badge-medium';
            badge.innerText = 'STOPPED / IDLE';
        }
    }

    if (packetsEl) packetsEl.innerText = (status.packets_captured || 0).toLocaleString();
    if (activeFlowsEl) activeFlowsEl.innerText = (status.active_flows || 0).toLocaleString();
    if (finalizedFlowsEl) finalizedFlowsEl.innerText = (status.finalized_flows || 0).toLocaleString();
    if (analyzedFlowsEl) analyzedFlowsEl.innerText = (status.analyzed_flows || 0).toLocaleString();
    if (detectionsEl) detectionsEl.innerText = (status.detections_count || 0).toLocaleString();
    if (alertsEl) alertsEl.innerText = (status.alerts_count || 0).toLocaleString();
    if (uptimeEl) uptimeEl.innerText = `${status.uptime_seconds || 0}s`;

    if (loopbackWarningBox) {
        loopbackWarningBox.style.display = status.is_loopback_warning ? 'block' : 'none';
    }

    if (errorBox) {
        if (status.last_error) {
            errorBox.style.display = 'block';
            errorBox.innerText = status.last_error;
        } else {
            errorBox.style.display = 'none';
        }
    }
}
