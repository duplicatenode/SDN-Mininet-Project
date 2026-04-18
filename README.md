# Assignment 5 — Packet Logger using SDN Controller
### Framework: POX · OpenFlow 1.0 · Python 2.7 / 3.x

---

## What This Project Does

An SDN Packet Logger built on the **POX** controller.  
Every packet that traverses the network triggers a `packet_in` event on the controller.  
The controller parses the packet and:

| Requirement | How it is met |
|---|---|
| Capture packet headers | Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP headers are all extracted |
| Identify protocol types | TCP / UDP / HTTP / HTTPS / ICMP / ARP / DNS / IPv4 / IPv6 / LLDP |
| Maintain logs | Written to `packet_log.txt`, `packet_log.csv`, `packet_log.json` |
| Display packet information | Real-time terminal output + `dashboard.html` |

---

## Files

```
packet_logger/
├── packet_logger.py   ← POX controller component  (copy into pox/ext/)
├── dashboard.html     ← Browser dashboard (open directly, no server needed)
└── README.md          ← This file
```

---

## FULL SETUP — Every Command, In Order

### ══ STEP 1 ── Install dependencies ══════════════════════════════

Open a terminal and run these one by one:

```bash
sudo apt update
sudo apt install -y git python3 python3-pip net-tools curl
```

---

### ══ STEP 2 ── Download POX ══════════════════════════════════════

```bash
cd ~
git clone https://github.com/noxrepo/pox.git
```

> This creates the folder `~/pox/`.  
> You do **not** need to install POX — it runs directly from the folder.

---

### ══ STEP 3 ── Copy the controller file ═════════════════════════

```bash
cp packet_logger.py ~/pox/ext/
```

> `ext/` is where POX looks for custom components.

Verify it is there:
```bash
ls ~/pox/ext/packet_logger.py
```

---

### ══ STEP 4 ── Install Mininet ══════════════════════════════════

```bash
sudo apt install -y mininet
```

Test the install:
```bash
sudo mn --test pingall
# You should see "Results: 0% dropped"
# Type "exit" to quit Mininet
```

---

### ══ STEP 5 ── Start the POX controller ═════════════════════════

Open **Terminal 1** and run:

```bash
cd ~/pox
python pox.py log.level --DEBUG packet_logger
```

You should see output like:
```
POX 0.x ... / ...
INFO:packet_logger:=================================================================
INFO:packet_logger:  SDN Packet Logger  –  POX OpenFlow Controller
INFO:packet_logger:  Logs: packet_log.txt | packet_log.csv | packet_log.json
INFO:packet_logger:=================================================================
INFO:core:POX 0.x.x is up
```

> Keep this terminal open. The controller listens on **port 6633** (POX default).

---

### ══ STEP 6 ── Start Mininet ════════════════════════════════════

Open **Terminal 2** (new terminal window):

```bash
sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo=tree,depth=2,fanout=3 --mac
```

This creates a tree topology:
```
        s1
       /  \
      s2   s3
    / | \  / | \
   h1 h2 h3 h4 h5 h6
```

You will see the `mininet>` prompt when it is ready.

Back in **Terminal 1** you should immediately see:
```
INFO:packet_logger:[Switch connected] DPID: 0000000000000001  –  table-miss flow installed
INFO:packet_logger:[Switch connected] DPID: 0000000000000002  –  table-miss flow installed
INFO:packet_logger:[Switch connected] DPID: 0000000000000003  –  table-miss flow installed
```

---

### ══ STEP 7 ── Generate traffic ═════════════════════════════════

In the **Mininet terminal** (`mininet>` prompt):

#### Ping all hosts (generates ICMP + ARP packets)
```
mininet> pingall
```

#### Ping between two specific hosts
```
mininet> h1 ping -c 5 h6
```

#### Run a web server and make HTTP requests
```
mininet> h1 python3 -m http.server 80 &
mininet> h2 curl http://10.0.0.1/
```

#### Run iperf bandwidth test (generates TCP/UDP traffic)
```
mininet> iperf h1 h6
```

#### Run individual host commands
```
mininet> h1 ifconfig
mininet> h3 ping -c 3 h5
```

#### Watch packets being logged (in Terminal 1)
```
[#0001] ARP    | 10.0.0.1:— → 10.0.0.2:— | 60 bytes | dpid=0000000000000001 port=1 | ARP Request: 10.0.0.1 → 10.0.0.2
[#0002] ICMP   | 10.0.0.1:— → 10.0.0.2:— | 98 bytes | dpid=0000000000000001 port=1 | ICMP Echo Request 10.0.0.1 → 10.0.0.2
[#0003] ICMP   | 10.0.0.2:— → 10.0.0.1:— | 98 bytes | dpid=0000000000000002 port=3 | ICMP Echo Reply 10.0.0.2 → 10.0.0.1
```

---

### ══ STEP 8 ── View the log files ═══════════════════════════════

Log files are written to `~/pox/` (the directory you launched `pox.py` from).

```bash
# Live tail — watch packets as they are captured
tail -f ~/pox/packet_log.txt

# View CSV (import into Excel / LibreOffice)
cat ~/pox/packet_log.csv

# View structured JSON
cat ~/pox/packet_log.json | python3 -m json.tool | head -60

# Count packets per protocol
awk -F',' 'NR>1{print $7}' ~/pox/packet_log.csv | sort | uniq -c | sort -rn
```

---

### ══ STEP 9 ── Open the dashboard ══════════════════════════════

Simply open `dashboard.html` in your browser:

```bash
xdg-open ~/packet_logger/dashboard.html
# or
firefox ~/packet_logger/dashboard.html
# or
google-chrome ~/packet_logger/dashboard.html
```

> No web server needed — it runs entirely in the browser.  
> The dashboard simulates live capture for demonstration purposes.  
> Press **▶ Capture** to see packets populate.  
> Click any row to inspect full packet header detail.  
> Use **↓ CSV** or **↓ JSON** to export from the dashboard.

---

### ══ STEP 10 ── Stop everything ════════════════════════════════

In the Mininet terminal:
```
mininet> exit
```

In the POX terminal:
```
Ctrl + C
```

Clean up Mininet state (run if you see errors next time):
```bash
sudo mn -c
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   POX Controller                    │
│                  packet_logger.py                   │
│                                                     │
│  ConnectionUp event                                 │
│    └─► Install table-miss flow on switch            │
│         (match: all  →  action: send to controller) │
│                                                     │
│  PacketIn event (fires for EVERY packet)            │
│    ├─► Parse Ethernet header                        │
│    ├─► Parse ARP / IPv4 / IPv6                      │
│    ├─► Parse TCP / UDP / ICMP                       │
│    ├─► Classify protocol (DNS, HTTP, HTTPS...)      │
│    ├─► Log → console, .txt, .csv, .json             │
│    └─► Flood packet out (network stays functional)  │
└───────────────────┬─────────────────────────────────┘
                    │ OpenFlow 1.0  (port 6633)
         ┌──────────▼──────────┐
         │   Mininet Switches  │
         │   s1, s2, s3 (OVS) │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │  Virtual Hosts      │
         │  h1 h2 h3 h4 h5 h6 │
         └─────────────────────┘
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Connection refused` on port 6633 | Make sure POX is running first (Step 5), then start Mininet (Step 6) |
| `RTNETLINK answers: File exists` | Run `sudo mn -c` to clean up leftover Mininet state |
| No packets appearing in Terminal 1 | Make sure you typed `pingall` in the Mininet terminal |
| `ImportError` in pox.py | Make sure `packet_logger.py` is inside `~/pox/ext/` |
| Permission denied on Mininet | Always run Mininet with `sudo` |
| POX says `pox.py: error: ...` | Use `python pox.py` not `python3 pox.py` (POX prefers Python 2, but works on 3) |

---

## Log File Formats

### packet_log.txt
```
[2024-01-15T10:23:45.123] PKT #0001 | Proto: ARP    | Src: 10.0.0.1:— | Dst: 10.0.0.2:— | Len: 60 bytes | TTL:  | Flags:  | DPID: 0000000000000001 Port: 1 | ARP Request: 10.0.0.1 → 10.0.0.2
```

### packet_log.csv columns
```
packet_id, timestamp, dpid, in_port, eth_src, eth_dst, protocol,
src_ip, dst_ip, src_port, dst_port, ttl, packet_len,
tcp_flags, icmp_type, icmp_code, arp_opcode, arp_src_ip, arp_dst_ip, info
```

### packet_log.json
```json
[
  {
    "packet_id": 1,
    "timestamp": "2024-01-15T10:23:45.123",
    "dpid": "0000000000000001",
    "in_port": 1,
    "eth_src": "00:00:00:00:00:01",
    "eth_dst": "ff:ff:ff:ff:ff:ff",
    "protocol": "ARP",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": "",
    "dst_port": "",
    "ttl": "",
    "packet_len": 60,
    "tcp_flags": "",
    "icmp_type": "",
    "icmp_code": "",
    "arp_opcode": "Request",
    "arp_src_ip": "10.0.0.1",
    "arp_dst_ip": "10.0.0.2",
    "info": "ARP Request: 10.0.0.1 → 10.0.0.2"
  }
]
```
