#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# God's Eye — ge-sensor Launch Script (macOS & Linux)
# ═══════════════════════════════════════════════════════════════════
# Uses ge-sensor --list-interfaces so device names match libpcap/Npcap.
# Usage: sudo ./launch.sh [--port 9090] [--config configs/ge-sensor.yml]

set -euo pipefail

C='\033[0;36m'  G='\033[0;32m'  Y='\033[0;33m'  R='\033[0;31m'
W='\033[1;37m'  D='\033[0;90m'  NC='\033[0m'

PORT="9090"
CONFIG="configs/ge-sensor.yml"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --port)   PORT="${2:?}"; shift 2 ;;
    --config) CONFIG="${2:?}"; shift 2 ;;
    *) shift ;;
  esac
done

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

UNAME_S="$(uname -s)"

# Primary IPv4 for a capture device name (empty if none / unsupported).
get_ipv4_for_iface() {
  local dev="$1"
  case "$UNAME_S" in
    Darwin)
      if command -v ipconfig >/dev/null 2>&1; then
        local a
        a="$(ipconfig getifaddr "$dev" 2>/dev/null || true)"
        if [ -n "$a" ]; then printf '%s' "$a"; return; fi
      fi
      if command -v ifconfig >/dev/null 2>&1; then
        ifconfig "$dev" 2>/dev/null | awk '
          $1 == "inet" && $2 != "127.0.0.1" { print $2; exit }
          $0 ~ /^[[:space:]]+inet / && $2 != "127.0.0.1" { print $2; exit }
        '
      fi
      ;;
    Linux)
      if command -v ip >/dev/null 2>&1; then
        ip -4 addr show dev "$dev" 2>/dev/null | awk '
          $1 == "inet" {
            sub(/\/.*/, "", $2)
            if ($2 != "127.0.0.1") { print $2; exit }
          }
        '
      elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig "$dev" 2>/dev/null | awk '$1 == "inet" && $2 != "127.0.0.1" { print $2; exit }'
      fi
      ;;
    *)
      if command -v ifconfig >/dev/null 2>&1; then
        ifconfig "$dev" 2>/dev/null | awk '$1 == "inet" && $2 != "127.0.0.1" { print $2; exit }'
      fi
      ;;
  esac
}

# Interfaces we avoid recommending for typical "see my LAN / Wi-Fi traffic" capture.
skip_for_recommend() {
  case "$1" in
    lo|lo0) return 0 ;;
    ap[0-9]*|ap) return 0 ;;
    awdl*|llw*|utun*) return 0 ;;
    bridge*|gif*|stf*) return 0 ;;
    anpi*) return 0 ;;
    docker*|veth*|virbr*|br-*|lxc*|cni*|vnet*) return 0 ;;
  esac
  return 1
}

has_ipv4() { [ -n "${1:-}" ]; }

# Sets global RECOMMENDED_NUM (1-based index into IFACE_NAMES) and RECOMMENDED_REASON.
pick_recommended() {
  local n="${#IFACE_NAMES[@]}"
  local i
  RECOMMENDED_NUM=1
  RECOMMENDED_REASON="first device in list"

  # 1) macOS: en0 with IPv4 (common primary)
  if [ "$UNAME_S" = Darwin ]; then
    for ((i = 0; i < n; i++)); do
      if [ "${IFACE_NAMES[i]}" = "en0" ] && has_ipv4 "${IFACE_IPV4[i]:-}"; then
        RECOMMENDED_NUM=$((i + 1))
        RECOMMENDED_REASON="en0 has a routable IPv4 (typical Wi-Fi / primary)"
        return
      fi
    done
  fi

  # 2) Linux / generic: eth0, wlan0, wlp*, ens*, enp* with IPv4
  for ((i = 0; i < n; i++)); do
    case "${IFACE_NAMES[i]}" in
      eth0|wlan0|wlp*|wl*|ens*|enp*)
        if has_ipv4 "${IFACE_IPV4[i]:-}"; then
          RECOMMENDED_NUM=$((i + 1))
          RECOMMENDED_REASON="common primary NIC with IPv4"
          return
        fi
        ;;
    esac
  done

  # 3) Any en* with IPv4 (Thunderbolt / USB Ethernet on Mac)
  for ((i = 0; i < n; i++)); do
    case "${IFACE_NAMES[i]}" in
      en[0-9]*)
        if has_ipv4 "${IFACE_IPV4[i]:-}" && ! skip_for_recommend "${IFACE_NAMES[i]}"; then
          RECOMMENDED_NUM=$((i + 1))
          RECOMMENDED_REASON="Ethernet-style en* with IPv4"
          return
        fi
        ;;
    esac
  done

  # 4) First non-skipped interface with IPv4
  for ((i = 0; i < n; i++)); do
    if ! skip_for_recommend "${IFACE_NAMES[i]}" && has_ipv4 "${IFACE_IPV4[i]:-}"; then
      RECOMMENDED_NUM=$((i + 1))
      RECOMMENDED_REASON="first non-virtual interface with IPv4"
      return
    fi
  done

  # 5) macOS en0 even without IPv4
  if [ "$UNAME_S" = Darwin ]; then
    for ((i = 0; i < n; i++)); do
      if [ "${IFACE_NAMES[i]}" = "en0" ]; then
        RECOMMENDED_NUM=$((i + 1))
        RECOMMENDED_REASON="en0 (no IPv4 detected — still usual primary NIC)"
        return
      fi
    done
  fi

  # 6) First non-skipped
  for ((i = 0; i < n; i++)); do
    if ! skip_for_recommend "${IFACE_NAMES[i]}"; then
      RECOMMENDED_NUM=$((i + 1))
      RECOMMENDED_REASON="first non-virtual interface in list"
      return
    fi
  done
}

clear 2>/dev/null || true

echo -e "${C}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║           GOD'S EYE — ge-sensor              ║"
echo "  ║    Network Capture & IDS/IPS Daemon          ║"
echo "  ║         macOS · Linux · libpcap              ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${D}Building ge-sensor...${NC}"
cargo build -q
BIN="$ROOT/target/debug/ge-sensor"
if [ ! -x "$BIN" ]; then
  echo -e "${R}✗ Build failed: missing $BIN${NC}" >&2
  exit 1
fi
echo -e "${G}✓${NC} Build complete"
echo ""

TMP_LIST="$(mktemp)"
trap 'rm -f "$TMP_LIST"' EXIT
if ! "$BIN" --list-interfaces > "$TMP_LIST"; then
  echo -e "${R}✗ Could not list interfaces. Install libpcap (e.g. apt install libpcap-dev).${NC}" >&2
  exit 1
fi

if [ ! -s "$TMP_LIST" ]; then
  echo -e "${R}✗ No capture devices reported by libpcap.${NC}" >&2
  exit 1
fi

declare -a IFACE_NAMES
declare -a IFACE_IPV4
declare -a IFACE_DESC

while IFS=$'\t' read -r _idx name desc || [ -n "${name:-}" ]; do
  [ -z "${name:-}" ] && continue
  IFACE_NAMES+=("$name")
  IFACE_DESC+=("${desc:-}")
  ip="$(get_ipv4_for_iface "$name" || true)"
  IFACE_IPV4+=("$ip")
done < "$TMP_LIST"

pick_recommended
DEFAULT_NUM="$RECOMMENDED_NUM"

echo -e "${W}Available capture devices:${NC}"
echo -e "${D}────────────────────────────────────────────────────────────────────────────${NC}"
printf "  ${D}%2s  %-12s  %-18s  %s${NC}\n" "#" "interface" "IPv4 address" "note"
echo -e "${D}────────────────────────────────────────────────────────────────────────────${NC}"

for i in "${!IFACE_NAMES[@]}"; do
  line_num=$((i + 1))
  name="${IFACE_NAMES[i]}"
  ip="${IFACE_IPV4[i]:-}"
  desc="${IFACE_DESC[i]:-}"
  if [ -n "$ip" ]; then
    ipdisp="$ip"
  else
    ipdisp="—"
  fi
  rec=""
  if [ "$line_num" -eq "$RECOMMENDED_NUM" ]; then
    rec="${Y}★ recommended${NC}"
  fi
  printf "  ${W}%2d${NC})  ${C}%-12s${NC}  ${G}%-18s${NC}  %b\n" "$line_num" "$name" "$ipdisp" "$rec"
  if [ -n "$desc" ]; then
    printf "      ${D}%s${NC}\n" "$desc"
  fi
done

echo -e "${D}────────────────────────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "${Y}Recommended:${NC} #${RECOMMENDED_NUM} ${C}${IFACE_NAMES[$((RECOMMENDED_NUM - 1))]}${NC} — ${D}${RECOMMENDED_REASON}${NC}"
echo ""

echo -ne "${W}Select device # ${D}[${DEFAULT_NUM}]${W}: ${NC}"
read -r SELECTION

if [ -z "${SELECTION:-}" ]; then
  CHOSEN_IDX="$DEFAULT_NUM"
elif echo "$SELECTION" | grep -qE '^[0-9]+$'; then
  CHOSEN_IDX="$SELECTION"
else
  echo -e "${R}✗ Enter a number from the list${NC}" >&2
  exit 1
fi

if [ "$CHOSEN_IDX" -lt 1 ] || [ "$CHOSEN_IDX" -gt "${#IFACE_NAMES[@]}" ]; then
  echo -e "${R}✗ Invalid selection${NC}" >&2
  exit 1
fi

SELECTED="${IFACE_NAMES[$((CHOSEN_IDX - 1))]}"

echo ""
echo -e "${G}✓${NC} Selected: ${C}${SELECTED}${NC}"
echo ""

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

exec "$BIN" \
  --config "$CONFIG" \
  --metrics-addr "0.0.0.0:${PORT}" \
  --interface "$SELECTED"
