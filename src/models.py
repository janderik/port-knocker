from dataclasses import dataclass, field
from enum import Enum

class ScanMode(Enum):
    SYN = "syn"
    CONNECT = "connect"
    FIN = "fin"
    NULL = "null"
    XMAS = "xmas"

@dataclass
class PortResult:
    port: int
    state: str = "closed"
    service: str = ""
    version: str = ""
    response_time: float = 0.0

@dataclass
class ScanResult:
    host: str
    ip_address: str = ""
    ports: list = field(default_factory=list)
    os_guess: str = ""
    scan_mode: ScanMode = ScanMode.SYN
    scan_duration: float = 0.0
    open_ports: int = 0
    closed_ports: int = 0
    filtered_ports: int = 0

KNOWN_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "smb", 993: "imaps", 995: "pop3s", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 27017: "mongodb", 5000: "flask/dev",
}
