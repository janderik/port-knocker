import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from .models import PortResult, ScanResult, ScanMode, KNOWN_SERVICES

class PortScanner:
    def __init__(self, host, ports, mode=ScanMode.CONNECT, threads=100, timeout=1.0):
        self.host = host
        self.ports = self._parse_ports(ports)
        self.mode = mode
        self.threads = threads
        self.timeout = timeout
        self.results = []
        self.lock = threading.Lock()

    def _parse_ports(self, ports):
        if isinstance(ports, list):
            return ports
        result = []
        for part in str(ports).split(','):
            if '-' in part:
                start, end = part.split('-', 1)
                result.extend(range(int(start), int(end) + 1))
            else:
                result.append(int(part))
        return sorted(set(result))

    def _resolve_host(self):
        try:
            return socket.gethostbyname(self.host)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve host: {self.host}")

    def _scan_port(self, port):
        result = PortResult(port=port)
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            code = sock.connect_ex((self.host, port))
            result.response_time = round((time.time() - start) * 1000, 2)
            if code == 0:
                result.state = "open"
                result.service = KNOWN_SERVICES.get(port, "unknown")
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % self.host.encode())
                    banner = sock.recv(256).decode(errors='ignore').strip()
                    if banner:
                        result.version = banner.split('\n')[0][:100]
                except Exception:
                    pass
            else:
                result.state = "closed"
            sock.close()
        except socket.timeout:
            result.state = "filtered"
            result.response_time = round((time.time() - start) * 1000, 2)
        except Exception:
            result.state = "closed"
        return result

    def run(self):
        ip = self._resolve_host()
        scan_result = ScanResult(host=self.host, ip_address=ip, scan_mode=self.mode)
        print(f"[*] Scanning {ip} ({len(self.ports)} ports)...")
        start = time.time()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in self.ports}
            for future in as_completed(futures):
                result = future.result()
                with self.lock:
                    self.results.append(result)
                if result.state == "open":
                    print(f"  [OPEN] {result.port}/{result.service} ({result.response_time}ms)")
        scan_result.ports = sorted(self.results, key=lambda r: r.port)
        scan_result.open_ports = sum(1 for r in self.results if r.state == 'open')
        scan_result.closed_ports = sum(1 for r in self.results if r.state == 'closed')
        scan_result.filtered_ports = sum(1 for r in self.results if r.state == 'filtered')
        scan_result.scan_duration = round(time.time() - start, 2)
        return scan_result
