Real-Time IoT Attack Detection (CPSC 483)

This project sets up a mini red-vs-blue lab:

Attacker VM (Kali): launches network attacks (SYN flood, Nmap scans, etc.).

Victim VM (Ubuntu 22.04): runs a real-time intrusion detector.

The detector uses a Random Forest model trained on the RT_IOT2022_processed.csv dataset to predict the attack type for each network flow in real time.

Core components:

train_rf.py – trains the Random Forest model.

detect_server.py – FastAPI server that loads the model and exposes /predict.

live_capture.py – uses Scapy to sniff traffic, build flow features, and send them to /predict.

random_attacks.sh – (optional) script on Kali to launch mixed attacks for testing.

1. High-Level Architecture

Kali (Attacker)

Sends traffic to the victim (e.g., using hping3, nmap, or random_attacks.sh).

Ubuntu (Victim)

live_capture.py sniffs packets on the interface connected to the attacker network (e.g., enp0s8).

It aggregates packets into flows, computes features that match the RT_IOT2022 dataset, and POSTs them as JSON to detect_server.py at http://127.0.0.1:8000/predict.

detect_server.py runs a FastAPI app that:

loads the trained Random Forest model (from models/attack_detector_rf.joblib),

maps input features to the model,

returns predicted Attack_type (raw + “nice label”) and class probabilities.

live_capture.py prints a log entry for each classified flow.

2. Prerequisites

Each student should have:

VirtualBox (or similar hypervisor).

Two VMs:

Kali Linux (attacker).

Ubuntu 22.04 (victim).

Basic familiarity with:

ip a, ping, sudo.

python3, pip, virtual environments.

3. Network Topology

For both VMs, use two adapters:

Adapter 1: NAT (for internet access – optional).

Adapter 2: Host-only or Internal Network (for attacker ↔ victim traffic).

Example (using Host-only):

Victim (Ubuntu): enp0s8 gets 192.168.107.10.

Attacker (Kali): eth1 gets 192.168.107.2.

Check on each VM:

ip a


You should see something like:

Ubuntu:

3: enp0s8: ... 
    inet 192.168.107.10/24 ...


Kali:

2: eth1: ...
    inet 192.168.107.2/24 ...


Make sure you can ping from Kali to Ubuntu:

ping 192.168.107.10

4. Files in This Project

On the Ubuntu (victim) VM, you’ll have a project folder, e.g.:

~/attack_detector/
    detect_server.py
    live_capture.py
    train_rf.py
    RT_IOT2022_processed.csv
    models/                 # created after training
        attack_detector_rf.joblib
    requirements.txt        # (we will create this)


On the Kali (attacker) VM, you’ll likely have:

~/attack_scripts/
    random_attacks.sh       # optional

5. Setting Up the Victim VM (Ubuntu 22.04)
5.1. Install system requirements

Update and install Python tools:

sudo apt update
sudo apt install -y python3 python3-venv python3-pip tcpdump


Optional: verify versions:

python3 --version
pip3 --version

5.2. Create project directory
mkdir -p ~/attack_detector
cd ~/attack_detector


Copy these files into this folder (via shared folder, scp, or drag-and-drop):

detect_server.py

live_capture.py

train_rf.py

RT_IOT2022_processed.csv

(Any helper files you’ve added)

5.3. Create and activate a virtual environment
cd ~/attack_detector

python3 -m venv attack-env
source attack-env/bin/activate


Now your prompt should look like:

(attack-env) vboxuser@Ubuntu22:~/attack_detector$

5.4. Install Python dependencies

Create a requirements.txt in ~/attack_detector with (at minimum):

fastapi
uvicorn[standard]
scikit-learn
pandas
numpy
joblib
scapy
requests


Then install:

pip install --upgrade pip
pip install -r requirements.txt


If you already have a requirements.txt from the project, just use that instead.

5.5. Train the Random Forest model

train_rf.py expects RT_IOT2022_processed.csv in the same directory and saves the model under models/attack_detector_rf.joblib.

Run:

cd ~/attack_detector
source attack-env/bin/activate

python3 train_rf.py


You should see output like:

Dataset shape

List of attack classes

Classification report

“Saved model bundle to …/models/attack_detector_rf.joblib”

5.6. Start the detection server (FastAPI + Uvicorn)

In a terminal on Ubuntu:

cd ~/attack_detector
source attack-env/bin/activate

uvicorn detect_server:app --host 0.0.0.0 --port 8000 --reload


You should see:

Uvicorn running on http://0.0.0.0:8000


Leave this running.

5.7. Configure and run live_capture.py

Open live_capture.py and make sure:

CAPTURE_IFACE is set to the interface that sees the attack traffic, e.g.:

CAPTURE_IFACE = "enp0s8"


DETECTOR_URL is:

DETECTOR_URL = "http://127.0.0.1:8000/predict"


Now, in another terminal on Ubuntu:

cd ~/attack_detector
source attack-env/bin/activate

sudo python3 live_capture.py


You should see:

[live_capture] Starting sniff on iface: enp0s8
[live_capture] Sending flow features to http://127.0.0.1:8000/predict


As attacks arrive, it will print one line per classified flow:

[2025-11-26T08:02:58.672024] Flow 192.168.107.2:3017 -> 192.168.107.10:80 proto=tcp,
pkts=5, bytes=298, pred=Attack: ARP poisoning (LOW CONF 0.28, raw=ARP_poisioning)


The key fields:

Flow src:port -> dst:port proto=...

pkts and bytes in the flow

pred=... – nice label + confidence + raw dataset label.

6. Setting Up the Attacker VM (Kali Linux)
6.1. Ensure network connectivity

On Kali:

ip a


Find the interface on the same subnet as Ubuntu (e.g., eth1 with 192.168.107.2).

Make sure:

ping 192.168.107.10


works.

6.2. Install attack tools

Most are preinstalled on Kali, but just in case:

sudo apt update
sudo apt install -y hping3 nmap tcpdump


(Optional) If you use random_attacks.sh, put it under e.g.:

mkdir -p ~/attack_scripts
cd ~/attack_scripts
# copy random_attacks.sh here
chmod +x random_attacks.sh

7. Launching Attacks and Observing Detection
7.1. SYN Flood (hping3)

On Kali:

sudo hping3 -S --flood -p 80 -s 40000 192.168.107.10


-S – sets SYN flag.

--flood – send packets as fast as possible.

-p 80 – target port 80 on the victim.

-s 40000 – fixed source port so the victim sees large flows instead of many tiny ones.

You’ll see:

hping in flood mode, no replies will be shown
^C
--- 192.168.107.10 hping statistic ---
5338254 packets transmitted, 0 packets received, 100% packet loss


That’s normal in flood mode.

On Ubuntu, live_capture.py will print a lot of flows with predictions, e.g.:

Flow 192.168.107.2:40000 -> 192.168.107.10:80 proto=tcp, pkts=XXX, bytes=YYYY,
pred=Attack: ARP poisoning (LOW CONF 0.30, raw=ARP_poisioning)


Even if the class is not exactly “DOS_SYN_Hping”, you can show:

The detector recognizes attack-like traffic.

It uses real-time features (flags, IATs, packet rates).

It returns an attack label + confidence.

7.2. Nmap Scan Examples

On Kali, you can run:

TCP scan:

sudo nmap -sS -Pn 192.168.107.10


UDP scan:

sudo nmap -sU -Pn 192.168.107.10


On Ubuntu, you may see things like:

pred=Recon: Nmap TCP scan (LOW CONF 0.23, raw=NMAP_TCP_scan)
pred=Recon: Nmap UDP scan (raw=NMAP_UDP_SCAN, max_proba=0.8)

8. Freezing and Sharing the Python Environment

Once your environment is working, you can “freeze” it so others can recreate the same versions.

From Ubuntu, inside the venv:

cd ~/attack_detector
source attack-env/bin/activate

pip freeze > requirements.txt


Now you can share requirements.txt with classmates. They can run:

python3 -m venv attack-env
source attack-env/bin/activate
pip install -r requirements.txt


to recreate the same Python environment.

9. Quick “From Zero to Demo” Summary

For your classmates, the shortest path:

On Ubuntu (victim):
# 1. Setup
sudo apt update
sudo apt install -y python3 python3-venv python3-pip tcpdump
mkdir -p ~/attack_detector
cd ~/attack_detector
# copy project files here (train_rf.py, detect_server.py, live_capture.py, CSV, requirements.txt)

python3 -m venv attack-env
source attack-env/bin/activate
pip install -r requirements.txt

# 2. Train model
python3 train_rf.py

# 3. Start detection server
uvicorn detect_server:app --host 0.0.0.0 --port 8000 --reload


In another Ubuntu terminal:

cd ~/attack_detector
source attack-env/bin/activate
sudo python3 live_capture.py

On Kali (attacker):
sudo apt update
sudo apt install -y hping3 nmap

# Example SYN flood attack:
sudo hping3 -S --flood -p 80 -s 40000 192.168.107.10

# Example Nmap scan:
sudo nmap -sS -Pn 192.168.107.10


Watch the Ubuntu live_capture terminal for predictions.
