# NetSec — Advanced Network Intelligence Platform

A professional cybersecurity web tool with a dark neon UI.

## Features

| Module | Description |
|---|---|
| **Nmap Scanner** | Full nmap integration — Basic, Full, Stealth, UDP, Aggressive, Ping sweep |
| **Subdomain Enumeration** | crt.sh Certificate Transparency + DNS resolution + nmap dns-brute |
| **MAC Identification** | ARP scan (nmap) + system ARP table + Scapy broadcast + OUI vendor lookup |
| **Packet Sniffer** | Live capture via Scapy — TCP/UDP/ICMP/ARP/HTTP/DNS/SSH/FTP detection |
| **Analytics** | Protocol pie chart, risk bar chart, packet timeline, host risk assessment |
| **Dashboard** | Live activity feed, scan history, quick scan, stats counters |

## Requirements

- Python 3.8+
- nmap installed (`sudo apt install nmap`)
- Root/sudo for packet sniffing & ARP
- Internet for crt.sh subdomain lookup & vendor API

## Installation & Run

```bash
# Clone or extract files into a folder
cd cybertools/

# Run as root (needed for sniffing + ARP)
sudo bash start.sh

# OR manually:
pip3 install -r requirements.txt --break-system-packages
sudo python3 app.py
```

Open browser → **http://localhost:5000**

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/nmap` | Run nmap scan |
| POST | `/api/subdomains` | Enumerate subdomains |
| POST | `/api/mac` | Identify MAC address |
| GET | `/api/interfaces` | List network interfaces |
| POST | `/api/sniff/start` | Start packet capture |
| GET | `/api/sniff/status/<id>` | Get packets + stats |
| POST | `/api/sniff/stop/<id>` | Stop capture |
| GET | `/api/sniff/export/<id>` | Export all packets as JSON |
| POST | `/api/discover` | Host discovery (ping sweep) |

## Nmap Scan Types

- **basic** — `-sV -sC --open -T4` (service version detection)
- **full** — `-sV -sC -O -A -T4` (OS + scripts + versions)
- **stealth** — `-sS -sV -T2` (SYN scan, low profile)
- **udp** — `-sU --top-ports 100` (UDP top 100)
- **aggressive** — `-A -T4 --script=vuln` (exploit scripts)
- **ping** — `-sn` (host discovery only)

## Subdomain Sources (No Wordlists)

1. **crt.sh** — Certificate Transparency logs (all historical SSL certs)
2. **Common prefixes** — 50+ genuine common subdomain names resolved via DNS
3. **nmap dns-brute** — nmap's built-in DNS brute script

## Notes

- Packet sniffing requires root (`sudo`)
- MAC identification only works on the **same local subnet** (ARP)
- Aggressive/vuln scan may take several minutes
- Use responsibly and only on networks you own/have permission to test
