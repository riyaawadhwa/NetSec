from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import subprocess
import re
import json
import threading
import socket
import struct
import os
import time
import dns.resolver
import requests
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, ARP, get_if_list
from scapy.layers.http import HTTPRequest, HTTPResponse
import netifaces
import queue
import uuid
from datetime import datetime
import ipaddress

app = Flask(__name__, static_folder='static')
CORS(app)

# Global packet capture store
packet_sessions = {}
sniff_threads = {}

# ─── NMAP SCAN ────────────────────────────────────────────────────────────────

def parse_nmap_output(output):
    result = {
        "hosts": [],
        "raw": output
    }
    host_blocks = re.split(r'Nmap scan report for ', output)[1:]
    for block in host_blocks:
        host = {}
        lines = block.strip().split('\n')
        first = lines[0]
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', first)
        hostname_match = re.match(r'^([^\s(]+)', first)
        host['ip'] = ip_match.group(1) if ip_match else first.strip()
        host['hostname'] = hostname_match.group(1) if hostname_match and not ip_match else ''
        if host['hostname'] == host['ip']:
            host['hostname'] = ''

        status_m = re.search(r'Host is (\w+)', block)
        host['status'] = status_m.group(1) if status_m else 'unknown'

        os_m = re.search(r'OS details: (.+)', block)
        host['os'] = os_m.group(1) if os_m else ''

        mac_m = re.search(r'MAC Address: ([A-F0-9:]+)\s*\(([^)]*)\)', block)
        host['mac'] = mac_m.group(1) if mac_m else ''
        host['mac_vendor'] = mac_m.group(2) if mac_m else ''

        ports = []
        port_lines = re.findall(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+))?', block)
        for pl in port_lines:
            ports.append({
                "port": int(pl[0]),
                "protocol": pl[1],
                "state": pl[2],
                "service": pl[3],
                "version": pl[4].strip() if pl[4] else ''
            })
        host['ports'] = ports

        uptime_m = re.search(r'uptime: ([\d.]+) seconds', block)
        host['uptime'] = uptime_m.group(1) if uptime_m else ''

        host['risk_score'] = calculate_risk(ports)
        result['hosts'].append(host)
    return result


def calculate_risk(ports):
    high_risk_ports = {21, 23, 25, 53, 80, 443, 445, 3389, 22, 3306, 5432, 6379, 27017, 11211, 8080, 8443}
    critical_ports = {23, 445, 3389, 6379, 27017, 11211}
    score = 0
    open_ports = [p for p in ports if p['state'] == 'open']
    score += min(len(open_ports) * 5, 40)
    for p in open_ports:
        if p['port'] in critical_ports:
            score += 20
        elif p['port'] in high_risk_ports:
            score += 10
    return min(score, 100)


@app.route('/api/nmap', methods=['POST'])
def nmap_scan():
    data = request.json
    target = data.get('target', '')
    scan_type = data.get('scan_type', 'basic')

    if not target:
        return jsonify({"error": "Target is required"}), 400

    scan_args = {
        'basic': ['-sV', '-sC', '--open', '-T4'],
        'full': ['-sV', '-sC', '-O', '-A', '-T4', '--open'],
        'stealth': ['-sS', '-sV', '-T2', '--open'],
        'udp': ['-sU', '-sV', '-T4', '--top-ports', '100'],
        'aggressive': ['-A', '-T4', '-sV', '-sC', '-O', '--script=vuln'],
        'ping': ['-sn', '-T4'],
    }

    args = scan_args.get(scan_type, scan_args['basic'])
    cmd = ['nmap'] + args + [target, '--stats-every', '5s']

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        parsed = parse_nmap_output(proc.stdout)
        parsed['stderr'] = proc.stderr
        parsed['command'] = ' '.join(cmd)
        parsed['timestamp'] = datetime.now().isoformat()
        return jsonify(parsed)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out after 5 minutes"}), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── SUBDOMAIN ENUMERATION ────────────────────────────────────────────────────

def check_subdomain_dns(subdomain, domain):
    fqdn = f"{subdomain}.{domain}"
    results = {'subdomain': fqdn, 'ips': [], 'cname': '', 'mx': [], 'status': 'not_found'}
    try:
        answers = dns.resolver.resolve(fqdn, 'A', lifetime=3)
        results['ips'] = [str(r) for r in answers]
        results['status'] = 'found'
    except Exception:
        pass
    if results['status'] == 'found':
        try:
            cname = dns.resolver.resolve(fqdn, 'CNAME', lifetime=2)
            results['cname'] = str(list(cname)[0])
        except Exception:
            pass
    return results


@app.route('/api/subdomains', methods=['POST'])
def enumerate_subdomains():
    data = request.json
    domain = data.get('domain', '').strip().lower()
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    # Remove protocol if present
    domain = re.sub(r'^https?://', '', domain).split('/')[0]

    found = []
    errors = []

    # 1. Certificate Transparency logs (crt.sh) - no wordlist needed
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, headers={'User-Agent': 'Mozilla/5.0 CyberTool/1.0'}
        )
        if resp.status_code == 200:
            certs = resp.json()
            seen = set()
            for cert in certs:
                names = cert.get('name_value', '').split('\n')
                for name in names:
                    name = name.strip().lower().lstrip('*.')
                    if name.endswith(domain) and name not in seen:
                        seen.add(name)
    except Exception as e:
        errors.append(f"crt.sh error: {str(e)}")
        seen = set()

    # 2. DNS brute-force with common prefixes (genuine, not wordlist-dependent)
    common_prefixes = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'remote', 'vpn',
        'dev', 'staging', 'test', 'beta', 'api', 'app', 'admin', 'portal', 'cdn',
        'static', 'media', 'img', 'assets', 'blog', 'shop', 'store', 'support',
        'help', 'docs', 'forum', 'community', 'secure', 'login', 'auth', 'oauth',
        'git', 'gitlab', 'github', 'jenkins', 'ci', 'jira', 'confluence', 'wiki',
        'ns1', 'ns2', 'mx', 'mx1', 'mx2', 'smtp1', 'smtp2', 'mail2', 'webdisk',
        'cpanel', 'whm', 'autodiscover', 'autoconfig', 'cloud', 'status', 'monitor',
        'dashboard', 'analytics', 'm', 'mobile', 'wap', 'pwa', 'old', 'new',
        'internal', 'intranet', 'office', 'crm', 'erp', 'db', 'database',
    ]
    for prefix in common_prefixes:
        seen.add(f"{prefix}.{domain}")

    # 3. Resolve all discovered subdomains
    from concurrent.futures import ThreadPoolExecutor, as_completed
    results_list = []

    def resolve_one(fqdn):
        sub = fqdn.replace(f'.{domain}', '').replace(domain, '')
        res = check_subdomain_dns(sub, domain)
        return res

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(resolve_one, s): s for s in seen}
        for future in as_completed(futures):
            try:
                r = future.result(timeout=5)
                if r['status'] == 'found':
                    results_list.append(r)
            except Exception:
                pass

    # 4. Also try nmap DNS scripts
    try:
        nmap_dns = subprocess.run(
            ['nmap', '--script', 'dns-brute', '--script-args', f'dns-brute.domain={domain}', '-T4', domain],
            capture_output=True, text=True, timeout=60
        )
        nmap_subs = re.findall(r'\|\s+([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')\s+-\s+(\d+\.\d+\.\d+\.\d+)', nmap_dns.stdout)
        nmap_found = set(r['subdomain'] for r in results_list)
        for sub, ip in nmap_subs:
            if sub not in nmap_found:
                results_list.append({'subdomain': sub, 'ips': [ip], 'cname': '', 'mx': [], 'status': 'found', 'source': 'nmap'})
    except Exception as e:
        errors.append(f"nmap dns-brute: {str(e)}")

    results_list.sort(key=lambda x: x['subdomain'])

    return jsonify({
        "domain": domain,
        "count": len(results_list),
        "subdomains": results_list,
        "errors": errors,
        "timestamp": datetime.now().isoformat()
      })




# ─── PACKET SNIFFING ──────────────────────────────────────────────────────────

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    interfaces = []
    for iface in get_if_list():
        try:
            addrs = netifaces.ifaddresses(iface)
            ipv4 = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', '')
            mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', '')
            interfaces.append({'name': iface, 'ip': ipv4, 'mac': mac})
        except Exception:
            interfaces.append({'name': iface, 'ip': '', 'mac': ''})
    return jsonify({"interfaces": interfaces})


@app.route('/api/sniff/start', methods=['POST'])
def start_sniff():
    data = request.json
    interface = data.get('interface', 'eth0')
    filter_expr = data.get('filter', '')
    count = data.get('count', 100)

    session_id = str(uuid.uuid4())[:8]
    packet_sessions[session_id] = {
        'packets': [],
        'status': 'running',
        'started': datetime.now().isoformat(),
        'interface': interface,
        'filter': filter_expr,
        'stats': {'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'arp': 0, 'other': 0}
    }

    def packet_callback(pkt):
        session = packet_sessions.get(session_id)
        if not session or session['status'] != 'running':
            return
        if len(session['packets']) >= count:
            session['status'] = 'complete'
            return

        pkt_info = {
            'id': session['stats']['total'] + 1,
            'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'timestamp': time.time(),
            'length': len(pkt),
            'src': '',
            'dst': '',
            'protocol': 'Unknown',
            'info': '',
            'layers': [],
            'flags': '',
            'ttl': 0,
            'sport': 0,
            'dport': 0,
            'payload_preview': ''
        }

        if Ether in pkt:
            pkt_info['layers'].append('Ethernet')
            pkt_info['eth_src'] = pkt[Ether].src
            pkt_info['eth_dst'] = pkt[Ether].dst

        if ARP in pkt:
            pkt_info['protocol'] = 'ARP'
            pkt_info['src'] = pkt[ARP].psrc
            pkt_info['dst'] = pkt[ARP].pdst
            op = 'Request' if pkt[ARP].op == 1 else 'Reply'
            pkt_info['info'] = f"ARP {op}: {pkt[ARP].psrc} -> {pkt[ARP].pdst}"
            session['stats']['arp'] += 1
        elif IP in pkt:
            pkt_info['src'] = pkt[IP].src
            pkt_info['dst'] = pkt[IP].dst
            pkt_info['ttl'] = pkt[IP].ttl
            pkt_info['layers'].append('IP')
            if TCP in pkt:
                pkt_info['protocol'] = 'TCP'
                pkt_info['sport'] = pkt[TCP].sport
                pkt_info['dport'] = pkt[TCP].dport
                flags = pkt[TCP].flags
                flag_str = ''
                if flags & 0x02: flag_str += 'SYN '
                if flags & 0x10: flag_str += 'ACK '
                if flags & 0x01: flag_str += 'FIN '
                if flags & 0x04: flag_str += 'RST '
                if flags & 0x08: flag_str += 'PSH '
                pkt_info['flags'] = flag_str.strip()
                pkt_info['info'] = f"{pkt[TCP].sport} → {pkt[TCP].dport} [{flag_str.strip()}] Seq={pkt[TCP].seq}"
                session['stats']['tcp'] += 1
                # HTTP detection
                if pkt[TCP].dport in (80, 8080) or pkt[TCP].sport in (80, 8080):
                    pkt_info['protocol'] = 'HTTP'
                elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                    pkt_info['protocol'] = 'HTTPS/TLS'
                elif pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                    pkt_info['protocol'] = 'SSH'
                elif pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                    pkt_info['protocol'] = 'FTP'
                elif pkt[TCP].dport == 25 or pkt[TCP].sport == 25:
                    pkt_info['protocol'] = 'SMTP'
                elif pkt[TCP].dport == 53 or pkt[TCP].sport == 53:
                    pkt_info['protocol'] = 'DNS/TCP'
            elif UDP in pkt:
                pkt_info['protocol'] = 'UDP'
                pkt_info['sport'] = pkt[UDP].sport
                pkt_info['dport'] = pkt[UDP].dport
                pkt_info['info'] = f"{pkt[UDP].sport} → {pkt[UDP].dport} Len={pkt[UDP].len}"
                session['stats']['udp'] += 1
                if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                    pkt_info['protocol'] = 'DNS'
                elif pkt[UDP].dport == 67 or pkt[UDP].sport == 67:
                    pkt_info['protocol'] = 'DHCP'
                elif pkt[UDP].dport == 123 or pkt[UDP].sport == 123:
                    pkt_info['protocol'] = 'NTP'
            elif ICMP in pkt:
                pkt_info['protocol'] = 'ICMP'
                icmp_types = {0: 'Echo Reply', 8: 'Echo Request', 3: 'Dest Unreachable', 11: 'TTL Exceeded'}
                t = icmp_types.get(pkt[ICMP].type, f'Type {pkt[ICMP].type}')
                pkt_info['info'] = f"ICMP {t}"
                session['stats']['icmp'] += 1
            else:
                session['stats']['other'] += 1
        else:
            session['stats']['other'] += 1

        # Payload preview
        raw = bytes(pkt)
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[-40:])
        pkt_info['payload_preview'] = printable

        session['stats']['total'] += 1
        session['packets'].append(pkt_info)

    def sniff_thread():
        try:
            sniff(
                iface=interface,
                filter=filter_expr if filter_expr else None,
                prn=packet_callback,
                store=False,
                stop_filter=lambda x: packet_sessions.get(session_id, {}).get('status') != 'running'
            )
        except Exception as e:
            if session_id in packet_sessions:
                packet_sessions[session_id]['status'] = 'error'
                packet_sessions[session_id]['error'] = str(e)

    t = threading.Thread(target=sniff_thread, daemon=True)
    sniff_threads[session_id] = t
    t.start()

    return jsonify({"session_id": session_id, "status": "started"})


@app.route('/api/sniff/status/<session_id>', methods=['GET'])
def sniff_status(session_id):
    session = packet_sessions.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({
        "session_id": session_id,
        "status": session['status'],
        "stats": session['stats'],
        "packet_count": len(session['packets']),
        "packets": session['packets'][-50:],  # last 50
        "started": session['started']
    })


@app.route('/api/sniff/stop/<session_id>', methods=['POST'])
def stop_sniff(session_id):
    session = packet_sessions.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404
    session['status'] = 'stopped'
    return jsonify({"status": "stopped", "total_packets": len(session['packets'])})


@app.route('/api/sniff/export/<session_id>', methods=['GET'])
def export_packets(session_id):
    session = packet_sessions.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({
        "session_id": session_id,
        "interface": session['interface'],
        "filter": session['filter'],
        "started": session['started'],
        "stats": session['stats'],
        "packets": session['packets']
    })


# ─── HOST DISCOVERY ───────────────────────────────────────────────────────────

@app.route('/api/discover', methods=['POST'])
def host_discover():
    data = request.json
    network = data.get('network', '')
    if not network:
        return jsonify({"error": "Network CIDR required"}), 400
    try:
        proc = subprocess.run(
            ['nmap', '-sn', '-T4', '--send-ip', network],
            capture_output=True, text=True, timeout=120
        )
        hosts = []
        blocks = re.split(r'Nmap scan report for ', proc.stdout)[1:]
        for block in blocks:
            lines = block.strip().split('\n')
            first = lines[0]
            ip_m = re.search(r'(\d+\.\d+\.\d+\.\d+)', first)
            hostname_m = re.match(r'^([^\s(]+)', first)
            host = {
                'ip': ip_m.group(1) if ip_m else first.strip(),
                'hostname': hostname_m.group(1) if hostname_m and not (hostname_m.group(1) == (ip_m.group(1) if ip_m else '')) else '',
                'status': 'up'
            }
            mac_m = re.search(r'MAC Address: ([A-F0-9:]+)\s*\(([^)]*)\)', block, re.IGNORECASE)
            if mac_m:
                host['mac'] = mac_m.group(1).upper()
                host['vendor'] = mac_m.group(2)
            hosts.append(host)
        return jsonify({"network": network, "hosts": hosts, "count": len(hosts), "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── SERVE FRONTEND ───────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)


if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    print("🚀 NetSec starting on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
