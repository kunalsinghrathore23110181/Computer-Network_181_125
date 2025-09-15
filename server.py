#!/usr/bin/env python3
import socket, json, argparse, csv
from scapy.all import DNS, rdpcap
from datetime import datetime
from tabulate import tabulate   # pip install tabulate

# ---------------- helpers ----------------
def parse_time_range(tr):
    s, e = tr.split('-')
    sh, sm = map(int, s.split(':'))
    eh, em = map(int, e.split(':'))
    smin = sh * 60 + sm
    emin = eh * 60 + em
    return smin, emin

def find_period(rules, hour, minute):
    tmin = hour * 60 + minute
    tb = rules['timestamp_rules']['time_based_routing']
    for name, info in tb.items():
        s, e = parse_time_range(info['time_range'])
        if s <= e:
            if s <= tmin <= e:
                return info
        else:
            if tmin >= s or tmin <= e:
                return info
    return None

def process_packet(rules, ip_pool, header, dns_bytes, addr, results):
    try:
        hh = int(header[0:2])
        mm = int(header[2:4])
        ss = int(header[4:6])
        sid = int(header[6:8])
    except Exception:
        print(f"⚠️ Invalid header: {header!r} from {addr}")
        return None, results

    info = find_period(rules, hh, mm)
    resolved = '0.0.0.0'
    if info:
        mod = info['hash_mod']
        pool_start = info['ip_pool_start']
        idx = pool_start + (sid % mod)
        if 0 <= idx < len(ip_pool):
            resolved = ip_pool[idx]

    domain = 'UNKNOWN'
    try:
        dns = DNS(dns_bytes)
        if dns.qdcount and dns.qd is not None:
            qname = dns.qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode(errors='ignore')
            domain = qname.rstrip('.')
    except Exception:
        pass

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Header={header} Domain={domain} -> {resolved} (from {addr})")
    results.append((header, domain, resolved))
    return resolved, results

# --------------- server main ----------------
def start_server(listen_ip, listen_port, rulesfile, out_csv='server_results.csv', pcap_file=None):
    with open(rulesfile) as f:
        rules = json.load(f)
    ip_pool = rules['ip_pool']
    results = []

    # --- Replay pcap first if provided ---
    if pcap_file:
        print(f"📂 Reading packets from {pcap_file} ...")
        packets = rdpcap(pcap_file)
        for i, pkt in enumerate(packets, 1):
            if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
                continue
            now = datetime.now()
            header = f"{now.hour:02d}{now.minute:02d}{now.second:02d}{i%100:02d}"
            resolved, results = process_packet(rules, ip_pool, header, bytes(pkt[DNS]), addr=("pcap", i), results=results)
        print("✅ Finished processing pcap file.\n")

    # --- Start live UDP server ---
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_ip, listen_port))
    print(f"✅ Server listening on {listen_ip}:{listen_port}\nWaiting for client queries...")

    try:
        while True:
            data, addr = sock.recvfrom(65535)
            if len(data) < 8:
                continue
            header = data[:8].decode('ascii', errors='ignore')
            dns_bytes = data[8:]
            resolved, results = process_packet(rules, ip_pool, header, dns_bytes, addr, results=results)
            if resolved:
                sock.sendto(resolved.encode('ascii'), addr)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
    finally:
        sock.close()

    # --- Print final table & save CSV ---
    print("\n📊 Final DNS Resolution Table:")
    print(tabulate(results, headers=['Custom Header', 'Domain', 'Resolved IP'], tablefmt='grid'))

    with open(out_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['custom_header', 'domain', 'resolved_ip'])
        writer.writerows(results)
    print(f"\n💾 Results saved to {out_csv}")

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--ip', default='0.0.0.0')
    p.add_argument('--port', type=int, default=53530)
    p.add_argument('--rules', default='rules.json')
    p.add_argument('--pcap', default=None, help="Optional path to a .pcap file")
    args = p.parse_args()

    # Use your default pcap if not specified
    default_pcap = r"C:\Users\kunal\OneDrive\Desktop\dns_resolver\6.pcap"
    pcap_file = args.pcap or default_pcap

    start_server(args.ip, args.port, args.rules, out_csv='server_results.csv', pcap_file=pcap_file)
