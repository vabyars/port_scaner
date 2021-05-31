import argparse
import socket
import sys

MAX_PORT = 65535


class Args:
    def __init__(self):
        self.host, self.start, self.end = self._parse_args()

    @staticmethod
    def _parse_args() -> tuple[str, int, int]:
        parser = argparse.ArgumentParser(description='TCP port scanner.')
        parser.add_argument("start_port", type=int, help="start port to scan", default=1)
        parser.add_argument("end_port", type=int, help="end port to scan", default=65536)
        parser.add_argument('--host', type=str, dest='host', default='localhost',
                            help='host to scan')
        args = parser.parse_args()
        try:
            start, end = int(args.start_port), int(args.end_port)
        except ValueError:
            print('Port number must be integer')
            sys.exit()
        if end > MAX_PORT:
            print('Port numbers must be less than 65535')
            sys.exit()
        if start > end:
            print('Invalid arguments')
            sys.exit()
        try:
            socket.gethostbyname(args.host)
        except socket.gaierror:
            print(f'Invalid host {args.host}')
            sys.exit()
        return args.host, start, end
