# VULNIX

### Code Intelligence & Security

**VULNIX** is an experimental static code analysis tool designed to identify selected security issues in Python code.

🌐 **Live application:** https://vulnix-f3iw.onrender.com/

## Features

- Python syntax analysis
- Detection of potentially dangerous functions such as `eval()` and `exec()`
- Detection of direct system commands using `os.system()`
- Detection of unsafe `pickle.loads()` usage
- Detection of `subprocess` calls with `shell=True`
- Detection of potentially hardcoded secrets
- Security recommendations with line and column information
- Risk score based on detected issues
- Web interface accessible from a browser

## Getting Started

### Requirements

- Python 3.8 or newer
- Git

### Run Locally

Clone the repository:

```bash
git clone https://github.com/BloxPulse/VULNIX.git
cd VULNIX
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Start VULNIX:

```bash
python3 app.py
```

Open the following address in your browser:

http://127.0.0.1:8765

## Deployment

VULNIX is publicly hosted on Render.

- Platform: Render
- Runtime: Python 3
- Start command: `python app.py`
- Health check: `/healthz`

## How It Works

VULNIX uses Python's Abstract Syntax Tree (AST) to inspect submitted source code.

The analyzer checks code patterns without executing the submitted Python code.

Detected issues are displayed with their severity, location, description and suggested improvement.

## Limitations

VULNIX 0.1 is experimental.

- Python is currently the only supported language.
- Detection relies on a limited set of predefined rules.
- False positives and missed vulnerabilities are possible.
- The security score is indicative and is not a guarantee of security.
- A clean analysis does not mean that code is completely secure.

Do not submit confidential source code, passwords or production secrets to the public service.

## Roadmap

Planned improvements:

- Additional Python security rules
- Improved detection accuracy
- Bug detection
- More detailed analysis reports
- Support for additional programming languages
- AI-assisted code analysis

## Project Information

**Project:** VULNIX
**Organization:** BloxPulse
**Current version:** 0.1
**Status:** Experimental

## License

Check the repository for licensing information.
