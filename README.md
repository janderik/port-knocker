# Port Knocker

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg) ![License](https://img.shields.io/badge/License-MIT-yellow.svg)

Fast TCP port scanner and service discovery tool.

## Features

- Multi-threaded SYN scanning
- Service and version detection
- OS fingerprinting hints
- Range and list scanning modes
- Output formats: text, JSON, CSV
- Stealth scan modes (SYN, FIN, NULL, XMAS)
- Host discovery before port scanning

## Quick Start

```bash
pip install -r requirements.txt
python -m src.main --host 192.168.1.1 --ports 1-1000
python -m src.main --host example.com --ports 22,80,443 --output results.json
```

## License

MIT
