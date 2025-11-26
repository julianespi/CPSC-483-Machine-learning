#!/usr/bin/env python3
"""
live_capture.py

Sniff packets on a given interface, aggregate them into 5-tuple flows,
compute a set of flow-level features that MATCH train_rf.py's ONLINE_FEATURES,
and send those to the detect_server.py FastAPI service for classification.

- Uses scapy to capture packets.
- Groups packets into flows by (src_ip, dst_ip, sport, dport, proto).
- Tracks:
    * Basic stats (pkts, bytes, duration, rates, ratio)
    * Categorical: proto, service
    * Payload stats
    * TCP flag counts
    * Inter-arrival times (IATs) for flow/fwd/bwd

- When a flow has been idle for FLOW_TIMEOUT seconds:
    * Build a feature dict using RT_IOT2022_processed.csv column names
      (subset used in ONLINE_FEATURES in train_rf.py).
    * POST to DETECTOR_URL with JSON:
          {"features": { ... }}
    * Print predicted Attack_type with confidence and raw label.

Usage:
    sudo python3 live_capture.py

IMPORTANT:
    CAPTURE_IFACE must match the interface that sees traffic from your Kali
    attacker (e.g., "enp0s8").
"""

import threading
import time
from datetime import datetime
from typing import Dict, Tuple, List
import statistics

import requests
from scapy.all import IP, TCP, UDP, Raw, sniff

# === CONFIG ===

# Where the detection server is running (usually on the same Ubuntu box)
DETECTOR_URL = "http://127.0.0.1:8000/predict"

# Network interface to sniff on (CHANGE THIS for your VM)
CAPTURE_IFACE = "enp0s8"

# Flow timeout in seconds (inactive flows will be flushed)
FLOW_TIMEOUT = 10.0

# Minimum number of packets before we bother sending the flow
MIN_PKTS_FOR_CLASSIFICATION = 15  # bumped up to reduce noise

# Minimum model confidence required before we consider a prediction "high confidence"
CONFIDENCE_THRESHOLD = 0.7

# Global flow table:
# key: (src_ip, dst_ip, sport, dport, proto_str)
# value: dict with counters and timestamps
flows: Dict[Tuple[str, str, int, int, str], Dict] = {}
flows_lock = threading.Lock()


def proto_to_str(pkt) -> str:
    if pkt.haslayer(TCP):
        return "tcp"
    if pkt.haslayer(UDP):
        return "udp"
    return "other"


def get_ports(pkt) -> Tuple[int, int]:
    sport, dport = 0, 0
    if pkt.haslayer(TCP):
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
    return sport, dport


def handle_packet(pkt) -> None:
    """Callback for each sniffed packet."""
    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    dst_ip = ip_layer.dst

    # --- Filter 1: skip obvious multicast/broadcast noise (mDNS, SSDP, etc.) ---
    if (
        dst_ip.startswith("224.")      # multicast
        or dst_ip.startswith("239.")   # multicast
        or dst_ip == "255.255.255.255" # broadcast
    ):
        return

    proto = proto_to_str(pkt)

    # --- Filter 2: ignore non-TCP/UDP protocols (model doesn't know them) ---
    if proto not in ("tcp", "udp"):
        return

    sport, dport = get_ports(pkt)

    # Optional: skip common noisy UDP services by port (mDNS, SSDP)
    if proto == "udp" and (sport in (5353, 1900) or dport in (5353, 1900)):
        return

    ts = float(pkt.time)
    size = int(len(pkt))

    fwd_key = (ip_layer.src, ip_layer.dst, sport, dport, proto)
    rev_key = (ip_layer.dst, ip_layer.src, dport, sport, proto)

    with flows_lock:
        if fwd_key in flows:
            key = fwd_key
            direction = "fwd"
        elif rev_key in flows:
            key = rev_key
            direction = "bwd"
        else:
            key = fwd_key
            direction = "fwd"
            flows[key] = {
                "src": ip_layer.src,
                "dst": ip_layer.dst,
                "sport": sport,
                "dport": dport,
                "proto": proto,
                "first_ts": ts,
                "last_ts": ts,
                "last_seen": ts,
                "pkt_count": 0,
                "byte_count": 0,
                "fwd_pkt_count": 0,
                "bwd_pkt_count": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,
                "fwd_payload_bytes": 0,
                "bwd_payload_bytes": 0,

                # TCP flag counters
                "flow_FIN_flag_count": 0,
                "flow_SYN_flag_count": 0,
                "flow_RST_flag_count": 0,
                "flow_ACK_flag_count": 0,
                "flow_CWR_flag_count": 0,
                "flow_ECE_flag_count": 0,
                "fwd_PSH_flag_count": 0,
                "bwd_PSH_flag_count": 0,
                "fwd_URG_flag_count": 0,
                "bwd_URG_flag_count": 0,

                # IAT tracking
                "last_flow_ts": None,
                "last_fwd_ts": None,
                "last_bwd_ts": None,
                "flow_iat_list": [],
                "fwd_iat_list": [],
                "bwd_iat_list": [],
            }

        flow = flows[key]
        flow["last_ts"] = ts
        flow["last_seen"] = ts
        flow["pkt_count"] += 1
        flow["byte_count"] += size

        # Payload size approximation
        payload_len = 0
        if pkt.haslayer(Raw):
            try:
                payload_len = len(pkt[Raw].load)
            except Exception:
                payload_len = 0

        if direction == "fwd":
            flow["fwd_pkt_count"] += 1
            flow["fwd_bytes"] += size
            flow["fwd_payload_bytes"] += payload_len
        else:
            flow["bwd_pkt_count"] += 1
            flow["bwd_bytes"] += size
            flow["bwd_payload_bytes"] += payload_len

        # --- TCP flag accounting ---
        if pkt.haslayer(TCP):
            flags = int(pkt[TCP].flags)
            # FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08,
            # ACK=0x10, URG=0x20, ECE=0x40, CWR=0x80

            if flags & 0x01:
                flow["flow_FIN_flag_count"] += 1
            if flags & 0x02:
                flow["flow_SYN_flag_count"] += 1
            if flags & 0x04:
                flow["flow_RST_flag_count"] += 1
            if flags & 0x10:
                flow["flow_ACK_flag_count"] += 1
            if flags & 0x40:
                flow["flow_ECE_flag_count"] += 1
            if flags & 0x80:
                flow["flow_CWR_flag_count"] += 1

            if direction == "fwd":
                if flags & 0x08:
                    flow["fwd_PSH_flag_count"] += 1
                if flags & 0x20:
                    flow["fwd_URG_flag_count"] += 1
            else:
                if flags & 0x08:
                    flow["bwd_PSH_flag_count"] += 1
                if flags & 0x20:
                    flow["bwd_URG_flag_count"] += 1

        # --- IAT tracking ---

        # Flow-level IAT (between any two packets in this flow)
        if flow["last_flow_ts"] is not None:
            dt_flow = ts - flow["last_flow_ts"]
            if dt_flow > 0:
                flow["flow_iat_list"].append(dt_flow)
        flow["last_flow_ts"] = ts

        # Directional IATs
        if direction == "fwd":
            if flow["last_fwd_ts"] is not None:
                dt_f = ts - flow["last_fwd_ts"]
                if dt_f > 0:
                    flow["fwd_iat_list"].append(dt_f)
            flow["last_fwd_ts"] = ts
        else:
            if flow["last_bwd_ts"] is not None:
                dt_b = ts - flow["last_bwd_ts"]
                if dt_b > 0:
                    flow["bwd_iat_list"].append(dt_b)
            flow["last_bwd_ts"] = ts


def iat_stats(lst: List[float]) -> Tuple[float, float, float, float, float]:
    """Return (min, max, tot, avg, std) for a list of IATs."""
    if not lst:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    i_min = min(lst)
    i_max = max(lst)
    i_tot = sum(lst)
    i_avg = i_tot / len(lst)
    i_std = statistics.pstdev(lst) if len(lst) > 1 else 0.0
    return i_min, i_max, i_tot, i_avg, i_std


def build_feature_vector(flow: Dict) -> Dict:
    """
    Map a flow dictionary into a partial feature vector using
    RT_IOT2022_processed.csv column names, matching ONLINE_FEATURES
    in train_rf.py.
    """
    first_ts = flow["first_ts"]
    last_ts = flow["last_ts"]
    duration = max(last_ts - first_ts, 1e-6)

    fwd_pkts = flow["fwd_pkt_count"]
    bwd_pkts = flow["bwd_pkt_count"]
    total_pkts = fwd_pkts + bwd_pkts

    fwd_bytes = flow["fwd_bytes"]
    bwd_bytes = flow["bwd_bytes"]
    total_bytes = fwd_bytes + bwd_bytes

    features: Dict[str, float] = {}

    # Categorical
    features["proto"] = flow["proto"]
    # Rough guess of service by port
    if flow["dport"] in (80, 8080, 8000):
        service = "http"
    elif flow["dport"] in (1883, 8883):
        service = "mqtt"
    elif flow["dport"] in (22,):
        service = "ssh"
    else:
        service = "other"
    features["service"] = service

    # Basic flow stats
    features["flow_duration"] = duration
    features["fwd_pkts_tot"] = float(fwd_pkts)
    features["bwd_pkts_tot"] = float(bwd_pkts)

    # Treat "data packets" as all packets for now
    features["fwd_data_pkts_tot"] = float(fwd_pkts)
    features["bwd_data_pkts_tot"] = float(bwd_pkts)

    features["fwd_pkts_per_sec"] = fwd_pkts / duration
    features["bwd_pkts_per_sec"] = bwd_pkts / duration
    features["flow_pkts_per_sec"] = total_pkts / duration

    # Down/up ratio = bwd / fwd (avoid div by zero)
    if fwd_pkts > 0:
        features["down_up_ratio"] = bwd_pkts / fwd_pkts
    else:
        features["down_up_ratio"] = 0.0

    # Approximate payload stats
    if fwd_pkts > 0:
        features["fwd_pkts_payload.avg"] = flow["fwd_payload_bytes"] / float(
            fwd_pkts
        )
    else:
        features["fwd_pkts_payload.avg"] = 0.0
    if bwd_pkts > 0:
        features["bwd_pkts_payload.avg"] = flow["bwd_payload_bytes"] / float(
            bwd_pkts
        )
    else:
        features["bwd_pkts_payload.avg"] = 0.0

    # Total bytes per second
    features["payload_bytes_per_second"] = total_bytes / duration

    # TCP flag features
    features["flow_FIN_flag_count"] = float(flow.get("flow_FIN_flag_count", 0))
    features["flow_SYN_flag_count"] = float(flow.get("flow_SYN_flag_count", 0))
    features["flow_RST_flag_count"] = float(flow.get("flow_RST_flag_count", 0))
    features["flow_ACK_flag_count"] = float(flow.get("flow_ACK_flag_count", 0))
    features["flow_CWR_flag_count"] = float(flow.get("flow_CWR_flag_count", 0))
    features["flow_ECE_flag_count"] = float(flow.get("flow_ECE_flag_count", 0))
    features["fwd_PSH_flag_count"] = float(flow.get("fwd_PSH_flag_count", 0))
    features["bwd_PSH_flag_count"] = float(flow.get("bwd_PSH_flag_count", 0))
    features["fwd_URG_flag_count"] = float(flow.get("fwd_URG_flag_count", 0))
    features["bwd_URG_flag_count"] = float(flow.get("bwd_URG_flag_count", 0))

    # IAT stats
    fwd_min, fwd_max, fwd_tot, fwd_avg, fwd_std = iat_stats(
        flow.get("fwd_iat_list", [])
    )
    bwd_min, bwd_max, bwd_tot, bwd_avg, bwd_std = iat_stats(
        flow.get("bwd_iat_list", [])
    )
    flw_min, flw_max, flw_tot, flw_avg, flw_std = iat_stats(
        flow.get("flow_iat_list", [])
    )

    features["fwd_iat.min"] = fwd_min
    features["fwd_iat.max"] = fwd_max
    features["fwd_iat.tot"] = fwd_tot
    features["fwd_iat.avg"] = fwd_avg
    features["fwd_iat.std"] = fwd_std

    features["bwd_iat.min"] = bwd_min
    features["bwd_iat.max"] = bwd_max
    features["bwd_iat.tot"] = bwd_tot
    features["bwd_iat.avg"] = bwd_avg
    features["bwd_iat.std"] = bwd_std

    features["flow_iat.min"] = flw_min
    features["flow_iat.max"] = flw_max
    features["flow_iat.tot"] = flw_tot
    features["flow_iat.avg"] = flw_avg
    features["flow_iat.std"] = flw_std

    return features


def flush_expired_flows() -> None:
    """Background thread: flush expired flows and classify them."""
    while True:
        now = time.time()
        to_flush = []

        with flows_lock:
            for key, flow in list(flows.items()):
                idle = now - flow["last_seen"]
                if idle > FLOW_TIMEOUT and flow["pkt_count"] >= MIN_PKTS_FOR_CLASSIFICATION:
                    to_flush.append((key, flow))
                    del flows[key]
                elif idle > FLOW_TIMEOUT:
                    # Too small to classify, just drop it
                    del flows[key]

        for key, flow in to_flush:
            features = build_feature_vector(flow)
            classify_flow(key, flow, features)

        time.sleep(1.0)


def classify_flow(key, flow, features: Dict) -> None:
    """Send flow features to the detector and print the prediction."""
    try:
        payload = {"features": features}
        resp = requests.post(DETECTOR_URL, json=payload, timeout=5)
        resp.raise_for_status()
        data = resp.json()

        # Nice (mapped) label from server
        pred = data.get("prediction", "UNKNOWN")

        # Raw Attack_type from dataset
        raw_pred = data.get("raw_prediction", pred)

        # Probabilities from server (list of floats)
        proba = data.get("probabilities")
        max_proba = None
        if isinstance(proba, list) and proba:
            max_proba = max(proba)

        # Decide what to display based on confidence
        if max_proba is not None and max_proba < CONFIDENCE_THRESHOLD:
            display_pred = (
                f"{pred} (LOW CONF {max_proba:.2f}, raw={raw_pred})"
            )
        elif max_proba is not None:
            display_pred = (
                f"{pred} (raw={raw_pred}, max_proba={max_proba:.2f})"
            )
        else:
            display_pred = f"{pred} (raw={raw_pred})"

    except Exception as e:
        print(f"[live_capture] Error sending flow for prediction: {e}")
        return

    ts = datetime.fromtimestamp(flow["last_ts"]).isoformat()
    src, dst, sport, dport, proto = key
    print(
        f"[{ts}] Flow {src}:{sport} -> {dst}:{dport} proto={proto}, "
        f"pkts={flow['pkt_count']}, bytes={flow['byte_count']}, pred={display_pred}"
    )


def main() -> None:
    print(f"[live_capture] Starting sniff on iface: {CAPTURE_IFACE}")
    print(f"[live_capture] Sending flow features to {DETECTOR_URL}")

    # Start the background flusher
    t = threading.Thread(target=flush_expired_flows, daemon=True)
    t.start()

    try:
        sniff(
            iface=CAPTURE_IFACE,
            prn=handle_packet,
            store=False,
        )
    except PermissionError:
        print(
            "PermissionError: run this script with sudo to capture packets "
            "(sudo python3 live_capture.py)"
        )
    except KeyboardInterrupt:
        print("[live_capture] Stopping sniff.")


if __name__ == "__main__":
    main()