# Security Lab - Penetration Testing Tools & Scripts

A collection of penetration testing and security research tools developed during CWEE and CPTS certification preparation. Each tool demonstrates offensive security techniques and attack methodologies for authorized security testing, research, and educational purposes.

## Tools & Scripts

### Web Application Attacks

#### NoSQL Time-Based Blind Injection Exploit
- **Location:** `web-apps/NoSQL/NoSQL-SSJI-time-based-blind.py`
- **Purpose:** Exploits time-based blind NoSQL injection vulnerabilities using binary search optimization
- **Target:** MongoDB and similar NoSQL databases vulnerable to Server-Side JavaScript Injection (SSJI)
- **Key Features:**
  - Efficient binary search algorithm for data extraction
  - Configurable protocol (HTTP/HTTPS), endpoints, and timing parameters
  - Burp Proxy integration for traffic inspection
  - Command-line interface with flexible configuration
- **Usage:** See `web-apps/NoSQL/Readme.md` for detailed documentation

## Quick Start

### Installation

```bash
# Clone repository
git clone <repo-url>
cd security-lab

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# NoSQL injection exploitation
python web-apps/NoSQL/NoSQL-SSJI-time-based-blind.py -H target.com:3000 -u admin -f password

# View help
python web-apps/NoSQL/NoSQL-SSJI-time-based-blind.py -h
```

## Prerequisites

- Python 3.7+
- `requests` library (see requirements.txt)
- Authorized access to target systems
- Understanding of attack techniques being employed

## Legal & Ethical Notice

**DISCLAIMER:** This repository is provided for educational and authorized security testing purposes only.

By using these tools, you acknowledge that:
- You have explicit written permission to test target systems
- You understand the legal implications of unauthorized computer system access
- You accept full responsibility for your actions
- Unauthorized access to computer systems is illegal in most jurisdictions

**The author holds no liability for misuse of these tools.**

## Target Audience

- Security professionals conducting authorized penetration tests
- Students preparing for CWEE, CPTS, and similar certifications
- Red team operators in authorized engagements
- Security researchers in controlled lab environments

## Documentation

Each tool directory contains a `Readme.md` with:
- Detailed vulnerability explanation
- Prerequisites and requirements
- Configuration guidance
- Usage examples and output

## Development Roadmap

Future additions planned:
- SQL injection enumeration tools
- Active Directory / LDAP enumeration
- Post-exploitation utilities
- C2 communication frameworks

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

Remember: With great power comes great responsibility. Use these tools ethically and legally.
