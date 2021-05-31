import socket
from concurrent.futures import ThreadPoolExecutor
import struct

from argparser import Args

PACKET = b'\x13' + b'\x00' * 39 + b'\x6f\x89\xe9\x1a\xb6\xd5\x3b\xd3'
DNS_TRANSACTION_ID = PACKET[:2]
SNTP_TIMESTAMP = PACKET[-8:]


def define_protocol(data):
    if b'HTTP' in data:
        return "HTTP"
    if DNS_TRANSACTION_ID in data:
        return "DNS"
    if data[:3].isdigit():
        return "SMTP"
    if data.startswith(b'+'):
        return "POP3"
    if is_sntp(data):
        return "SNTP"
    return "Undefined protocol"


def scan_udp(host, port):
    socket.setdefaulttimeout(3)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as scanner:
        try:
            scanner.sendto(PACKET, (host, port))
            data, _ = scanner.recvfrom(1024)
            return f'UDP {port} {define_protocol(data)}'
        except socket.error:
            pass


def is_sntp(packet):
    origin_timestamp = packet[24:32]
    is_packet_from_server = 7 & packet[0] == 4
    return len(packet) >= 48 and \
           is_packet_from_server and \
           origin_timestamp == SNTP_TIMESTAMP


def scan_tcp(host, port):
    socket.setdefaulttimeout(0.5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
        except (socket.timeout, TimeoutError, OSError):
            pass
        try:
            s.send(struct.pack('!H', len(PACKET)) + PACKET)
            data = s.recv(1024)
            return f"TCP {port} {define_protocol(data)}"
        except socket.error:
            pass


def scan(host, port):
    show(scan_tcp(host, port))
    show(scan_udp(host, port))


def show(result: str):
    if result:
        print(result)


def main():
    args = Args()
    print(f"Start scanning open ports in the range from {args.start} to {args.end} on the host {args.host}...\n")
    with ThreadPoolExecutor(max_workers=200) as tr:
        for port in range(args.start, args.end + 1):
            tr.submit(scan, args.host, port)


if __name__ == '__main__':
    main()
