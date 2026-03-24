#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# God's Eye — ge-sensor Launch Script
# ═══════════════════════════════════════════════════════════════════
# Usage: sudo ./launch.sh [--port 9090]

# ── Colors ──
C='\033[0;36m'  G='\033[0;32m'  Y='\033[0;33m'  R='\033[0;31m'
W='\033[1;37m'  D='\033[0;90m'  NC='\033[0m'

PORT="9090"
CONFIG="configs/ge-sensor.yml"

# Parse args
for arg in "$@"; do
  case "$prev" in
    --port)   PORT="$arg" ;;
    --config) CONFIG="$arg" ;;
  esac
  prev="$arg"
done

clear

# ── Banner ──
echo -e "${C}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║           GOD'S EYE — ge-sensor              ║"
echo "  ║    Network Capture & IDS/IPS Daemon          ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Discover interfaces ──
echo -e "${W}Available network interfaces:${NC}"
echo -e "${D}─────────────────────────────────────────────${NC}"

IFACES=()
IDX=1

for IFACE_NAME in $(ifconfig -l 2>/dev/null || echo "lo0 en0"); do
  # Get IP address if any
  IP_ADDR=$(ifconfig "$IFACE_NAME" 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1 || true)

  # Determine description
  DESC=""
  case "$IFACE_NAME" in
    en0)     DESC="Wi-Fi" ;;
    en1)     DESC="Thunderbolt" ;;
    lo0)     DESC="Loopback" ;;
    bridge*) DESC="Bridge" ;;
    utun*)   DESC="VPN Tunnel" ;;
    awdl*)   DESC="AirDrop" ;;
    llw*)    DESC="Low-Lat WLAN" ;;
    gif*)    DESC="Tunnel" ;;
    stf*)    DESC="6to4" ;;
    ap*)     DESC="Access Point" ;;
    anpi*)   DESC="ANPI" ;;
    *)       DESC="" ;;
  esac

  # Status dot
  if [ -n "$IP_ADDR" ]; then
    SC="${G}●${NC}"
  else
    SC="${D}○${NC}"
  fi

  IFACES+=("$IFACE_NAME")

  printf "  ${SC}  ${W}%2d${NC})  ${C}%-12s${NC}" "$IDX" "$IFACE_NAME"
  [ -n "$DESC" ] && printf "  ${D}%-14s${NC}" "$DESC"
  [ -n "$IP_ADDR" ] && printf "  ${G}%s${NC}" "$IP_ADDR"
  echo ""

  IDX=$((IDX + 1))
done

echo -e "${D}─────────────────────────────────────────────${NC}"
echo ""

# ── Auto-detect default ──
DEFAULT_IFACE="lo0"
for i in "${!IFACES[@]}"; do
  if [ "${IFACES[$i]}" = "en0" ]; then
    CHECK=$(ifconfig en0 2>/dev/null | grep 'inet ' || true)
    if [ -n "$CHECK" ]; then
      DEFAULT_IFACE="en0"
      break
    fi
  fi
done

# ── Prompt ──
echo -ne "${W}Select interface ${D}[${DEFAULT_IFACE}]${W}: ${NC}"
read -r SELECTION

if [ -z "$SELECTION" ]; then
  SELECTED="$DEFAULT_IFACE"
elif echo "$SELECTION" | grep -qE '^[0-9]+$'; then
  IDX=$((SELECTION - 1))
  if [ "$IDX" -ge 0 ] && [ "$IDX" -lt "${#IFACES[@]}" ]; then
    SELECTED="${IFACES[$IDX]}"
  else
    echo -e "${R}✗ Invalid selection${NC}"
    exit 1
  fi
else
  SELECTED="$SELECTION"
fi

echo ""
echo -e "${G}✓${NC} Selected: ${C}${SELECTED}${NC}"
echo ""

# ── Build ──
echo -e "${D}Building ge-sensor...${NC}"
cargo build 2>&1 | tail -1
echo -e "${G}✓${NC} Build complete"
echo ""

# ── Launch info ──
echo -e "${D}═══════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${G}●${NC}  Sensor:     ${W}ge-sensor${NC}"
echo -e "  ${G}●${NC}  Interface:  ${C}${SELECTED}${NC}"
echo -e "  ${G}●${NC}  Dashboard:  ${C}http://localhost:${PORT}${NC}"
echo -e "  ${G}●${NC}  API:        ${C}http://localhost:${PORT}/api/state${NC}"
echo -e "  ${G}●${NC}  Metrics:    ${C}http://localhost:${PORT}/metrics${NC}"
echo -e "  ${G}●${NC}  Config:     ${D}${CONFIG}${NC}"
echo ""
echo -e "${D}═══════════════════════════════════════════════${NC}"
echo ""
echo -e "${D}Press Ctrl+C to stop${NC}"
echo ""

# ── Run ──
exec ./target/debug/ge-sensor \
  --config "$CONFIG" \
  --metrics-addr "0.0.0.0:${PORT}" \
  --interface "$SELECTED" 2>&1
