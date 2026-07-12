import json
import csv
import io
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class Reporter:
    def print_results(self, result):
        table = Table(title=f"Scan Results: {result.host} ({result.ip_address})")
        table.add_column("Port", style="cyan", width=8)
        table.add_column("State", width=10)
        table.add_column("Service", style="green")
        table.add_column("Version")
        table.add_column("RTT (ms)", justify="right")
        for port in result.ports:
            state_style = {"open": "bold green", "filtered": "yellow", "closed": "red"}.get(port.state, "")
            table.add_row(str(port.port), f"[{state_style}]{port.state}[/{state_style}]", port.service, port.version, str(port.response_time))
        console.print(table)
        summary = f"Host: {result.host} ({result.ip_address})\nOpen: {result.open_ports} | Closed: {result.closed_ports} | Filtered: {result.filtered_ports}\nDuration: {result.scan_duration}s"
        console.print(Panel(summary, title="Summary", border_style="cyan"))

    def to_json(self, result):
        return json.dumps({
            "host": result.host, "ip_address": result.ip_address,
            "scan_mode": result.scan_mode.value, "duration": result.scan_duration,
            "summary": {"open": result.open_ports, "closed": result.closed_ports, "filtered": result.filtered_ports},
            "ports": [{"port": p.port, "state": p.state, "service": p.service, "version": p.version, "rtt_ms": p.response_time} for p in result.ports]
        }, indent=2)

    def to_csv(self, result):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["port", "state", "service", "version", "rtt_ms"])
        for p in result.ports:
            writer.writerow([p.port, p.state, p.service, p.version, p.response_time])
        return output.getvalue()

    def save(self, result, filepath, fmt="json"):
        content = self.to_json(result) if fmt == "json" else self.to_csv(result) if fmt == "csv" else self.to_json(result)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"[+] Results saved to {filepath}")
