# VULNIX

### Code Intelligence & Security

VULNIX is an experimental code analysis tool.

## Features

- Python syntax analysis
- Basic security issue detection
- Hardcoded secret detection
- Security recommendations
- Local web interface

## Installation

Requirements: Python 3.8+

```bash
git clone https://github.com/BloxPulse/VULNIX.git
cd VULNIX

python3 -m venv .venv
source .venv/bin/activate

python app.py
```
Open http://127.0.0.1:8765 in your browser.

## Limitations

VULNIX 0.1 is experimental.
It does not guarantee that code is free of vulnerabilities.
It currently analyzes Python code only.
The analyzer never executes submitted code.

## Roadmap

- More security checks
- Bug detection
- Additional programming languages
- AI-assisted analysis
- Detailed reports
