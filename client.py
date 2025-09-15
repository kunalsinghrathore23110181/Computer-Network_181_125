#!/usr/bin/env python3
import socket, argparse
from scapy.all import DNS, DNSQR

def build_packet(query, sid=1):
    # Custom header: HHMMSS + ID (fixed 8 chars)
    from datetime import datetime
    now = datetime.now()
    header = f"{now.hour:02d}{now.minute:02d}{now.second:02d}{sid:02d}"
    dns = DNS(rd=1, qd=DNSQR(qname=query))
    return header.encode() + bytes(dns)

def send_query(server_ip, server_port, query):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet = build_packet(query)
    sock.sendto(packet, (server_ip, server_port))
    try:
        data, _ = sock.recvfrom(1024)
        print(f"✅ Query: {query} -> Resolved IP: {data.decode(errors='ignore')}")
    except socket.timeout:
        print("⏳ Timeout waiting for response.")
    finally:
        sock.close()

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--server-ip', required=True, help="Server IP to connect to")
    p.add_argument('--server-port', type=int, required=True, help="Server port")
    p.add_argument('--query', required=True, help="Domain to resolve")
    args = p.parse_args()

    send_query(args.server_ip, args.server_port, args.query)
