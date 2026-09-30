#!/usr/bin/env bash
# ==============================================================================
# Intelligent Network Security Monitoring System using AI (AI-NSMS)
# Master Operational CLI Entry Point
# ==============================================================================

set -o pipefail

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${PROJECT_ROOT}" || exit 1

# Ensure logs directory exists
mkdir -p "${PROJECT_ROOT}/logs"
mkdir -p "${PROJECT_ROOT}/data"

echo -e "${CYAN}${BOLD}"
echo "========================================================================"
echo "🛡️  Intelligent Network Security Monitoring System (AI-NSMS)"
echo "   Real-Time AI-Based Network Intrusion Detection & SOC Operations"
echo "========================================================================"
echo -e "${NC}"

# ------------------------------------------------------------------------------
# 1. Dependency & Environment Check
# ------------------------------------------------------------------------------
echo -e "${BLUE}[1/5] Checking Environment & Dependencies...${NC}"

# Detect Python
PYTHON_BIN=""
if [ -f "${PROJECT_ROOT}/venv/bin/python" ]; then
    PYTHON_BIN="${PROJECT_ROOT}/venv/bin/python"
    echo -e "  ${GREEN}✓${NC} Using Virtualenv: ${PROJECT_ROOT}/venv"
elif command -v python3 &>/dev/null; then
    PYTHON_BIN="python3"
    echo -e "  ${YELLOW}!${NC} Using System Python: $(command -v python3)"
else
    echo -e "  ${RED}✗ Error: Python 3 is not installed or not in PATH.${NC}"
    exit 1
fi

# Verify Essential Python Libraries
MISSING_DEPS=0
for pkg in scapy flask joblib sklearn pandas numpy; do
    if ! "${PYTHON_BIN}" -c "import ${pkg}" &>/dev/null; then
        echo -e "  ${RED}✗ Missing package: ${pkg}${NC}"
        MISSING_DEPS=$((MISSING_DEPS + 1))
    fi
done

if [ ${MISSING_DEPS} -gt 0 ]; then
    echo -e "\n${RED}Error: ${MISSING_DEPS} required dependencies are missing.${NC}"
    echo "Please install them via: pip install -r requirements.txt"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} All Python dependencies verified."

# Check Model Artifacts
MODELS_DIR="${PROJECT_ROOT}/models"
if [ ! -f "${MODELS_DIR}/classifier_model.joblib" ] || [ ! -f "${MODELS_DIR}/anomaly_model.joblib" ]; then
    echo -e "  ${RED}✗ Error: Trained model artifacts not found in ${MODELS_DIR}.${NC}"
    echo "Please ensure classifier_model.joblib and anomaly_model.joblib are present."
    exit 1
fi
echo -e "  ${GREEN}✓${NC} AI Models verified (Random Forest Classifier + Isolation Forest Anomaly Detector)."

# Direct Mode Handlers
if [ "$1" == "dashboard" ] || [ "$1" == "web" ] || [ "$1" == "ui" ]; then
    echo -e "\n${CYAN}${BOLD}🚀 Launching SOC Dashboard Server in foreground...${NC}"
    echo -e "Press Ctrl+C to stop the dashboard server.\n"
    exec "${PYTHON_BIN}" "${PROJECT_ROOT}/src/dashboard.py"
fi

if [ "$1" == "monitor" ] || [ "$1" == "sniff" ]; then
    if [ "$EUID" -ne 0 ]; then
        echo -e "\n${YELLOW}⚡ Live packet capture requires root privileges. Elevating via sudo...${NC}"
        exec sudo "$0" "$@"
    fi
    shift
    echo -e "\n${CYAN}${BOLD}🚀 Launching Real-Time Packet Sniffer in foreground...${NC}\n"
    exec "${PYTHON_BIN}" "${PROJECT_ROOT}/src/realtime_monitor.py" "$@"
fi

# ------------------------------------------------------------------------------
# 2. Check Raw Packet Capture Capabilities (Root / Sudo)
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[2/5] Checking Packet Capture Privileges...${NC}"
if [ "$EUID" -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} Running with root/superuser privileges (CAP_NET_RAW enabled)."
else
    echo -e "  ${YELLOW}!${NC} Notice: Running as unprivileged user ($(whoami))."
    echo -e "  ${CYAN}⚡ Live packet capture requires raw socket privileges. Elevating via sudo...${NC}\n"
    exec sudo "$0" "$@"
fi

# ------------------------------------------------------------------------------
# 3. Network Interface Discovery & Selection
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[3/5] Discovering Host Network Interfaces...${NC}"

# Query interfaces cleanly via interface_discovery CLI (no syntax or escaping issues)
INTERFACE_INFO=$("${PYTHON_BIN}" "${PROJECT_ROOT}/src/engine/interface_discovery.py")

declare -a IFACE_NAMES
declare -a IFACE_INFOS
DEFAULT_IFACE_INDEX=1
CURRENT_IDX=1

while IFS='|' read -r num name itype status ip mac; do
    [ -z "$name" ] && continue
    IFACE_NAMES[CURRENT_IDX]="$name"
    IFACE_INFOS[CURRENT_IDX]="${name} (${itype}, Status: ${status}, IPv4: ${ip})"
    # Auto-select the first UP physical/Wi-Fi interface with an IPv4 address
    if [ "$status" == "UP" ] && [ "$name" != "lo" ] && [ "$ip" != "No IPv4" ]; then
        DEFAULT_IFACE_INDEX=$CURRENT_IDX
    fi
    CURRENT_IDX=$((CURRENT_IDX + 1))
done <<< "${INTERFACE_INFO}"

TOTAL_IFACES=$((CURRENT_IDX - 1))

if [ "$TOTAL_IFACES" -eq 0 ]; then
    echo -e "  ${YELLOW}!${NC} No interfaces discovered dynamically. Falling back to default list."
    IFACE_NAMES[1]="wlp108s0"
    IFACE_INFOS[1]="wlp108s0 (Wi-Fi Default)"
    IFACE_NAMES[2]="lo"
    IFACE_INFOS[2]="lo (Loopback)"
    TOTAL_IFACES=2
    DEFAULT_IFACE_INDEX=1
fi

echo -e "\n${CYAN}------------------------------------------------------------------------${NC}"
echo -e "${BOLD}🌐 Available Network Interfaces:${NC}"
echo -e "${CYAN}------------------------------------------------------------------------${NC}"
for i in $(seq 1 $TOTAL_IFACES); do
    if [ "$i" -eq "$DEFAULT_IFACE_INDEX" ]; then
        echo -e "  [${BOLD}${i}${NC}] ${GREEN}${BOLD}${IFACE_INFOS[i]}${NC}  <-- (${CYAN}Recommended Default${NC})"
    else
        echo -e "  [${i}] ${IFACE_INFOS[i]}"
    fi
done
echo -e "${CYAN}------------------------------------------------------------------------${NC}"

# Check if interface passed via CLI argument ($1 or -i)
CHOSEN_IFACE=""
if [ -n "$1" ] && [ "$1" != "-h" ] && [ "$1" != "--help" ]; then
    ARG_VAL="$1"
    if [ "$ARG_VAL" == "-i" ] && [ -n "$2" ]; then
        ARG_VAL="$2"
    fi
    # If a number was passed
    if [[ "$ARG_VAL" =~ ^[0-9]+$ ]] && [ "$ARG_VAL" -ge 1 ] && [ "$ARG_VAL" -le "$TOTAL_IFACES" ]; then
        CHOSEN_IFACE="${IFACE_NAMES[ARG_VAL]}"
    else
        CHOSEN_IFACE="$ARG_VAL"
    fi
    echo -e "\n  Target Interface specified via argument: ${GREEN}${BOLD}${CHOSEN_IFACE}${NC}"
else
    # Interactive prompt without timeout so user can comfortably choose
    while true; do
        echo -e ""
        read -p "Select Interface [1-${TOTAL_IFACES}] or enter interface name (Press Enter for default [${DEFAULT_IFACE_INDEX}] - ${IFACE_NAMES[DEFAULT_IFACE_INDEX]}): " USER_SELECTION
        
        # If user pressed Enter, accept the default
        if [ -z "$USER_SELECTION" ]; then
            CHOSEN_IFACE="${IFACE_NAMES[DEFAULT_IFACE_INDEX]}"
            break
        fi

        # If user entered a valid number
        if [[ "$USER_SELECTION" =~ ^[0-9]+$ ]] && [ "$USER_SELECTION" -ge 1 ] && [ "$USER_SELECTION" -le "$TOTAL_IFACES" ]; then
            CHOSEN_IFACE="${IFACE_NAMES[USER_SELECTION]}"
            break
        fi

        # If user typed the name of an interface directly (e.g. wlp108s0, eth0, lo)
        MATCHED=false
        for i in $(seq 1 $TOTAL_IFACES); do
            if [ "${IFACE_NAMES[i]}" == "$USER_SELECTION" ]; then
                CHOSEN_IFACE="${IFACE_NAMES[i]}"
                MATCHED=true
                break
            fi
        done

        if [ "$MATCHED" = true ]; then
            break
        fi

        # If user typed an arbitrary interface name, confirm or use it
        if [ -n "$USER_SELECTION" ]; then
            CHOSEN_IFACE="$USER_SELECTION"
            break
        fi

        echo -e "${RED}Invalid selection. Please choose a number between 1 and ${TOTAL_IFACES} or press Enter.${NC}"
    done
fi

echo -e "\n  ${GREEN}✓${NC} Selected Network Interface: ${GREEN}${BOLD}${CHOSEN_IFACE}${NC}"
if [ "$CHOSEN_IFACE" == "lo" ]; then
    echo -e "  ${YELLOW}⚠️  Warning: Loopback interface selected. Only local 127.0.0.1 traffic will be monitored.${NC}"
fi

# ------------------------------------------------------------------------------
# 4. Start SOC Operations Web Dashboard (Background Process)
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[4/5] Starting SOC Operations Web Dashboard...${NC}"

DASHBOARD_PORT=5000
DASHBOARD_LOG="${PROJECT_ROOT}/logs/dashboard.log"

# Clean up any old zombie dashboard instances
pkill -f "src/dashboard.py" 2>/dev/null || true
sleep 0.5

# Spawn Dashboard server
"${PYTHON_BIN}" "${PROJECT_ROOT}/src/dashboard.py" > "${DASHBOARD_LOG}" 2>&1 &
DASHBOARD_PID=$!
echo -e "  ${GREEN}✓${NC} Dashboard server spawned (PID: ${DASHBOARD_PID})"
echo -e "  ${GREEN}✓${NC} Logging to: ${DASHBOARD_LOG}"
sleep 1.5

# Dynamically parse which port it bound to
DETECTED_PORT=$(grep -oE "http://[0-9a-zA-Z.:]+:[0-9]+" "${DASHBOARD_LOG}" 2>/dev/null | tail -n 1 | grep -oE "[0-9]+$")
DASHBOARD_PORT="${DETECTED_PORT:-5000}"

echo -e "  ${CYAN}${BOLD}🌐 SOC Dashboard URL:${NC} http://localhost:${DASHBOARD_PORT}"
echo -e "  👤 Admin Account:    admin   / Admin@12345"
echo -e "  👤 Analyst Account:  analyst / Analyst@12345"


# ------------------------------------------------------------------------------
# 5. Trap Signals for Clean Graceful Shutdown
# ------------------------------------------------------------------------------
cleanup() {
    echo -e "\n\n${YELLOW}[SHUTDOWN] Stopping AI-NSMS services gracefully...${NC}"
    if [ -n "${DASHBOARD_PID}" ] && kill -0 "${DASHBOARD_PID}" 2>/dev/null; then
        echo -e "  ${YELLOW}→${NC} Terminating Dashboard server (PID: ${DASHBOARD_PID})..."
        kill -SIGTERM "${DASHBOARD_PID}" 2>/dev/null || true
        wait "${DASHBOARD_PID}" 2>/dev/null || true
    fi
    echo -e "${GREEN}✓ AI-NSMS shutdown complete. Stay secure!${NC}\n"
    exit 0
}

trap cleanup SIGINT SIGTERM SIGHUP

# ------------------------------------------------------------------------------
# 6. Start Live Network Monitoring (Foreground Process)
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[5/5] Launching Real-Time Packet Sniffing & AI Intrusion Detection...${NC}"
echo -e "${CYAN}------------------------------------------------------------------------${NC}"
echo -e "• Interface:        ${BOLD}${CHOSEN_IFACE}${NC}"
echo -e "• BPF Filter:       ${BOLD}ip${NC}"
echo -e "• Flow Timeout:     ${BOLD}10.0s${NC}"
echo -e "• AI Engine:        ${BOLD}Random Forest (0.55 threshold) + Isolation Forest + Heuristics${NC}"
echo -e "• Live Dashboard:   ${BOLD}http://localhost:${DASHBOARD_PORT}/monitoring${NC}"
echo -e "${CYAN}------------------------------------------------------------------------${NC}"
echo -e "${YELLOW}Press Ctrl+C at any time to stop monitoring cleanly.${NC}\n"

# Execute RealTimeMonitor
"${PYTHON_BIN}" "${PROJECT_ROOT}/src/realtime_monitor.py" -i "${CHOSEN_IFACE}" -f "ip" -t 10.0

# Trigger cleanup when monitor exits
cleanup
