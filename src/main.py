import argparse
import concurrent.futures
import contextlib
import ipaddress
import random
import socket
import struct

from scapy.all import IP, TCP, sr1

INITAL_PORT = 1
FINAL_PORT = 65535


def parser_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--host", "--host", help="Host")
    parser.add_argument("--port", "--port", help="Port", required=False)
    args = parser.parse_args()

    if args.host:
        print(args.host)

    if args.port:
        print(args.port)

    return args.host, args.port


def check_host_ports(host):
    print(f"scanning ports on host {host}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(scan_full_tcp_host, host, _port)
            for _port in range(INITAL_PORT, FINAL_PORT + 1)
        ]
        concurrent.futures.wait(futures)


def scan_syc_ack(host, port):
    # Construct a SYN packet
    syn_packet = IP(dst=host) / TCP(dport=port, flags="S")

    # Send the SYN packet and receive the response
    response = sr1(syn_packet, timeout=1, verbose=0)

    # Check the response
    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x12:  # SYN-ACK
            print(f"Port {port} on host {host} is open.")
        elif response[TCP].flags == 0x14:  # RST-ACK
            print(f"Port {port} on host {host} is closed.")
    else:
        print(f"No response received from {host} on port {port}.")


def scan_full_tcp_host(host, port):
    with contextlib.suppress(Exception):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((host, port))
        sock.close()
        print(f"Port {port} is open")


if __name__ == "__main__":
    host, port = parser_args()

    if "*" in host:
        new_host = host.replace("*", "0/24")

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(check_host_ports, ip_host)
                for ip_host in ipaddress.IPv4Network(new_host, strict=False)
            ]

    if host and port:
        scan_full_tcp_host(host, port)

    if host and not port:
        scan_syc_ack(host, 22)

    print("Scan Finish")
