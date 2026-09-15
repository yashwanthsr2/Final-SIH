#!/usr/bin/env bash
# ==============================================================================
# CyberSentinel (SIH26-26145) — Kali Linux Live Passive Monitoring Launcher
# Organization: National Technical Research Organisation (NTRO)
# STRICT PASSIVE & READ-ONLY: Zero packet injection, zero active scanning,
# zero MITM, zero payload decryption.
# ==============================================================================

set -e

# ANSI Color Codes
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "======================================================================"
echo "    CYBERSENTINEL — NTRO AI THREAT INTELLIGENCE (SIH26-26145)        "
echo "        KALI LINUX REAL-TIME PASSIVE MONITORING SYSTEM                "
echo "======================================================================"
echo -e "${NC}"

# Check for root / sudo privileges (required for AF_PACKET & Zeek live capture)
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Error: Live passive network capture requires root privileges.${NC}"
  echo -e "    Please run with: ${BOLD}sudo bash run_kali_sensor.sh${NC}"
  exit 1
fi

echo -e "${GREEN}[✓] Root privilege confirmed.${NC}"

# 1. Interface Detection
echo -e "\n${YELLOW}[*] Detecting available network interfaces...${NC}"
INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo")
echo -e "Available interfaces:\n${INTERFACES}"

# Find default Wi-Fi interface (wlan0, wlp*, etc.)
DEFAULT_IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^wl' | head -n 1)

if [ -z "$DEFAULT_IFACE" ]; then
    DEFAULT_IFACE="wlan0"
    echo -e "${YELLOW}[!] No active wlan* detected automatically. Defaulting to '${DEFAULT_IFACE}'.${NC}"
else
    echo -e "${GREEN}[✓] Detected active Wi-Fi interface: ${BOLD}${DEFAULT_IFACE}${NC}"
fi

# Allow user to specify custom interface
read -p "Enter interface to monitor [Default: ${DEFAULT_IFACE}]: " USER_IFACE
IFACE=${USER_IFACE:-$DEFAULT_IFACE}

echo -e "\n${CYAN}[*] Target Interface selected: ${BOLD}${IFACE}${NC}"

# Ensure interface is UP
ip link set dev "${IFACE}" up 2>/dev/null || true

# 2. Check Python Environment
echo -e "\n${YELLOW}[*] Checking Python environment...${NC}"
if command -v python3 &>/dev/null; then
    PYTHON_BIN="python3"
elif command -v python &>/dev/null; then
    PYTHON_BIN="python"
else
    echo -e "${RED}[!] Python is not installed. Please install Python 3.10+${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Using Python: $(${PYTHON_BIN} --version)${NC}"

# 3. Check for Zeek (Preferred Passive Sensor)
echo -e "\n${YELLOW}[*] Checking Zeek (Bro) passive sensor...${NC}"
ZEEK_BIN=""
if command -v zeek &>/dev/null; then
    ZEEK_BIN="zeek"
elif [ -f "/opt/zeek/bin/zeek" ]; then
    ZEEK_BIN="/opt/zeek/bin/zeek"
    export PATH=$PATH:/opt/zeek/bin
fi

if [ -n "${ZEEK_BIN}" ]; then
    ZEEK_VER=$(${ZEEK_BIN} --version 2>&1 | head -n 1)
    echo -e "${GREEN}[✓] Zeek found: ${ZEEK_VER}${NC}"
    echo -e "    Primary passive sensor engine: ${BOLD}Zeek Live Tailing Engine${NC}"
else
    echo -e "${YELLOW}[!] Zeek not found in PATH or /opt/zeek/bin.${NC}"
    echo -e "    CyberSentinel will automatically use the built-in ${BOLD}Linux AF_PACKET / Scapy Passive Sniffer${NC}."
    echo -e "    To install Zeek on Kali Linux (recommended for high-speed zero-loss):"
    echo -e "        ${BOLD}sudo apt-get update && sudo apt-get install -y zeek${NC}"
fi

# 4. Check Python Dependencies
echo -e "\n${YELLOW}[*] Verifying required Python packages...${NC}"
${PYTHON_BIN} -c "import fastapi, uvicorn, scapy, psutil, joblib, sklearn, xgboost, lightgbm" 2>/dev/null || {
    echo -e "${YELLOW}[!] Missing some packages. Installing requirements...${NC}"
    ${PYTHON_BIN} -m pip install -r requirements.txt
}
echo -e "${GREEN}[✓] Python dependencies verified.${NC}"

# 5. Export configuration
export CYBERSENTINEL_INTERFACE="${IFACE}"
export CYBERSENTINEL_PASSIVE_ONLY=1
export CYBERSENTINEL_BASELINE_AUTOSTART=1

# 6. Launch CyberSentinel
HOST="0.0.0.0"
PORT="8000"

echo -e "\n${GREEN}${BOLD}======================================================================"
echo "    STARTING CYBERSENTINEL SERVER (PASSIVE WI-FI MONITORING)"
echo "======================================================================${NC}"
echo -e "  • Interface:         ${BOLD}${IFACE}${NC}"
echo -e "  • Web Dashboard:     ${BOLD}http://127.0.0.1:${PORT}${NC} or ${BOLD}http://$(hostname -I | awk '{print $1}'):${PORT}${NC}"
echo -e "  • Mode:              ${BOLD}Passive Read-Only Monitoring${NC}"
echo -e "  • Privacy:           ${BOLD}Metadata Only (Payload NOT Inspected)${NC}"
echo -e "  • Baseline:          ${BOLD}5-Minute Normal Baseline Calibration Enabled${NC}"
echo -e "======================================================================\n"

# Run Uvicorn
exec ${PYTHON_BIN} -m uvicorn app.main:app --host "${HOST}" --port "${PORT}"
