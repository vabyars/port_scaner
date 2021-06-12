import socket
from concurrent.futures import ThreadPoolExecutor

from argparser import Args
import packages

recognizers = [(packages.build_http_packet, packages.is_http_package, "HTTP"),
               (packages.build_smtp_packet, packages.is_smtp_package, "SMTP"),
               (packages.build_pop3_packet, packages.is_pop3_package, "POP3"),
               (packages.build_dns_package, packages.is_dns_package, "DNS"),
               (packages.build_ntp_packet, packages.is_ntp_package, "SNTP")]


def scan_application_layer(sock):
    for builder, recognizer, answer in recognizers:
        try:
            sock.settimeout(0.05)
            sock.send(builder())
            response = sock.recv(2048)
            if recognizer(response):
                return answer
        except:
            pass


def scan_udp(host, port):
    socket.setdefaulttimeout(3)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as scanner:
        try:
            udp_connect = scanner.connect_ex((host, port))

            if udp_connect == 0:
                application_layer = scan_application_layer(scanner)
                if application_layer:
                    return f'UDP {port} {application_layer if application_layer else ""}'
        except socket.error as e:
            pass


def scan_tcp(host, port):
    socket.setdefaulttimeout(0.5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            tcp_connect = s.connect_ex((host, port))
            if tcp_connect == 0:
                application_layer = scan_application_layer(s)
                return f'TCP {port} {application_layer if application_layer else ""}'
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
