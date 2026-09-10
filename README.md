# Security Lab - Penetration Testing Tools & Scripts

A collection of penetration testing and security research tools developed during CWEE and CPTS certification preparation. Each tool demonstrates offensive security techniques and attack methodologies for authorized security testing, research, and educational purposes.

## Tool Catalogue

| Category | Tool | Description | Location |
|---|---|---|---|
| Web Application Attacks | NoSQL Time-Based Blind Injection | Exploits time-based blind NoSQL/SSJI vulnerabilities via binary search extraction | [`web-apps/NoSQL/`](web-apps/NoSQL/Readme.md) |
| Windows Post-Exploitation | Find-Secrets | Recursively scans a host for assigned secrets (passwords, keys, connection strings) and parses unattend/autounattend/sysprep answer files for credentials | [`windows-privesc/Find-Secrets/`](windows-privesc/Find-Secrets/README.md) |
| Windows Post-Exploitation | Find-WritableDirs | Recursively finds directories writable by a given identity via non-inherited ACEs (writable-service-path / DLL-hijack privesc) | [`windows-privesc/Find-WritableDirs/`](windows-privesc/Find-WritableDirs/README.md) |

Each tool's own README covers usage, configuration, and requirements in detail — this table is the index.

## Installation

```bash
# Clone repository
git clone git@github.com:Pentesting-tech/security-lab.git
cd security-lab

# Install Python dependencies (used by web-apps/ tools)
pip install -r requirements.txt
```

Windows PowerShell tools (`windows-privesc/`) need no installation — see each
tool's README for requirements and usage.

## Prerequisites

- Python 3.7+ and the `requests` library for Python-based tools (see `requirements.txt`)
- Windows PowerShell 2.0+ for PowerShell-based tools (no external modules)
- Authorized access to target systems
- Understanding of the attack techniques being employed

## Usage & License

**DISCLAIMER:** This repository is provided for educational and authorized security testing purposes only.

By using these tools, you acknowledge that:
- You have explicit written permission to test target systems
- You understand the legal implications of unauthorized computer system access
- You will only use these tools for legitimate penetration testing, security research, or CTF competitions
- You accept full responsibility for your actions

**The author holds no liability for:**
- Unauthorized access or damage caused by misuse of these tools
- Legal consequences resulting from improper use
- Any harm caused by using these scripts on systems without proper authorization

These tools are intended for use by security professionals in controlled environments with proper authorization. Unauthorized access to computer systems is illegal in most jurisdictions.

## Target Audience

- Security professionals conducting authorized penetration tests
- Students preparing for CWEE, CPTS, and similar certifications
- Red team operators in authorized engagements
- Security researchers in controlled lab environments

## Usage Guidelines

All tools require:
1. Explicit written authorization from system owner
2. Lab environment or approved testing scope
3. Understanding of potential impact
4. Proper documentation and reporting

## License & Author

Created by: Pentesting-tech  
For educational and authorized security testing use only

---

Remember: Use these tools ethically and legally.
