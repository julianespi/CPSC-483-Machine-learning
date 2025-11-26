# Real-Time IoT Attack Detection (CPSC 483)

This project sets up a **mini red-vs-blue lab**:

- **Attacker VM** (Kali): launches network attacks (SYN flood, Nmap scans, etc.). only need random_atttacks.sh
- **Victim VM** (Ubuntu 22.04): runs a **real-time intrusion detector**.
- The detector uses a **Random Forest model** trained on the **RT_IOT2022_processed.csv** dataset to predict the **attack type** for each network flow in real time.

## 1. High-Level Architecture

1. **Kali (Attacker)**  
   - Sends traffic to the victim (e.g., using `hping3`, `nmap`, or `random_attacks.sh`).
2. **Ubuntu (Victim)**  
   - `live_capture.py` sniffs packets on the interface connected to the attacker network.
   - It aggregates packets into flows and POSTs them to `detect_server.py` (`/predict`).
   - `detect_server.py` runs a FastAPI app that loads the trained model and predicts attack types.

## 2. Prerequisites

- VirtualBox
- Two VMs: **Kali Linux** and **Ubuntu 22.04**
- Python3, pip, venv

## 3. Network Topology

Use two adapters:

1. NAT (for internet)
2. Host-only (for internal lab traffic)

Example IPs:

- Ubuntu: `192.168.107.10`
- Kali: `192.168.107.2`

Check interfaces using:

```
ip a
```

## 4. Project Structure (Ubuntu VM)

```
~/attack_detector/
    detect_server.py
    live_capture.py
    train_rf.py
    data/
       RT_IOT2022_processed.csv
    models/
    requirements.txt
```

## 5. Setting Up the Victim VM

### Install dependencies

```
sudo apt update
sudo apt install -y python3 python3-venv python3-pip tcpdump
```

### Create venv

```
cd ~/attack_detector
python3 -m venv attack-env
source attack-env/bin/activate
```

### Install requirements

```
pip install --upgrade pip
pip install -r requirements.txt
```

### Train the model

```
python3 train_rf.py
```

### Start the detection server

```
uvicorn detect_server:app --host 0.0.0.0 --port 8000 --reload
```

### Start live packet capture

```
sudo python3 live_capture.py
```

## 6. Setting Up the Attacker VM

### Ensure connectivity

```
ping 192.168.107.10
```

### Example attacks

**SYN Flood:**

```
sudo hping3 -S --flood -p 80 -s 40000 192.168.107.10
```

**Nmap Scan:**

```
sudo nmap -sS -Pn 192.168.107.10
```

## 7. Freezing Environment

```
pip freeze > requirements.txt
```

## 8. Quick Summary

Ubuntu:

```
python3 -m venv attack-env
source attack-env/bin/activate
pip install -r requirements.txt
python3 train_rf.py
uvicorn detect_server:app --host 0.0.0.0 --port 8000 --reload
sudo python3 live_capture.py
```

Kali:

```
sudo hping3 -S --flood -p 80 -s 40000 192.168.107.10
sudo nmap -sS -Pn 192.168.107.10
```
