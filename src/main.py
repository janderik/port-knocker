import argparse
from .scanner import PortScanner
from .reporter import Reporter
from .models import ScanMode

def main():
    parser = argparse.ArgumentParser(description='Port Knocker - Port Scanner')
    parser.add_argument('--host', '-H', required=True, help='Target host')
    parser.add_argument('--ports', '-p', default='1-1024', help='Ports: 80,443 or 1-1024')
    parser.add_argument('--mode', choices=['connect', 'syn'], default='connect')
    parser.add_argument('--threads', '-t', type=int, default=100)
    parser.add_argument('--timeout', type=float, default=1.0)
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--format', choices=['json', 'csv'], default='json')
    args = parser.parse_args()

    mode = ScanMode.SYN if args.mode == 'syn' else ScanMode.CONNECT
    scanner = PortScanner(args.host, args.ports, mode=mode, threads=args.threads, timeout=args.timeout)
    reporter = Reporter()

    try:
        result = scanner.run()
        reporter.print_results(result)
        if args.output:
            reporter.save(result, args.output, args.format)
    except ValueError as e:
        print(f"[-] Error: {e}")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")

if __name__ == '__main__':
    main()
