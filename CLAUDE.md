# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

Security Lab is a curated collection of penetration testing and offensive security tools developed for CWEE/CPTS certification preparation. Each tool targets specific attack vectors (web, network, post-exploitation) and is designed for authorized security testing only.

**Current Focus:** Building a portfolio of diverse, well-documented security tools to demonstrate mid-level penetration testing expertise.

## Project Structure

```
security-lab/
├── README.md                           # Main repo documentation (tools index, quick start, legal notice)
├── CLAUDE.md                           # This file
├── requirements.txt                    # Python dependencies (currently: requests)
├── web-apps/                           # Web application attack tools
│   └── NoSQL/
│       ├── NoSQL-SSJI-time-based-blind.py    # Time-based blind NoSQL injection exploit
│       └── Readme.md                         # Tool-specific documentation (technical details only)
```

## Adding New Tools

When adding a new pentesting script or tool, follow this structure:

### Directory Organization
- Create category subdirectory: `web-apps/`, `network/`, `post-exploitation/`, etc.
- Place script in appropriate category
- Include individual `Readme.md` with technical documentation only (no license duplicates)

### Script Requirements
- **CLI Interface:** Use `argparse` for all configurable parameters
- **Error Handling:** Proper exception handling and exit codes
- **Module Docstring:** Explain attack technique and purpose
- **Comments:** Only for non-obvious logic (hidden constraints, workarounds)
- **No Hardcoding:** All targets, credentials, endpoints configurable via CLI

### Documentation Standards
Each tool's `Readme.md` should include:
- What vulnerability/technique it exploits
- Prerequisites (what needs to be true about the target)
- Configuration guidance with examples
- References to external resources (OWASP, PortSwigger, etc.)
- **Do NOT duplicate:** Legal notice or usage disclaimers (reference main README instead)

### Python Standards
- Support Python 3.7+
- Add new dependencies to `requirements.txt`
- Use standard library first; avoid heavy dependencies
- Follow script structure of existing NoSQL tool (oracle function pattern, main execution)

## Development Workflow

### Before Adding/Modifying Tools
1. Ensure target is educational/authorized use case
2. Verify script is configurable (no hardcoded sensitive data)
3. Test with example usage
4. Add/update `requirements.txt` for new dependencies

### Commit Guidelines
- One tool/feature per commit when possible
- Example: `"Add SQL injection enumeration tool"` or `"Update NoSQL documentation"`
- Include why (attack vector, educational value) in commit messages for portfolio clarity

### Testing & Validation
- Verify CLI help: `python script.py -h`
- Document example usage in tool's README
- Ensure error messages are clear and actionable
- Test timeout/retry logic works as expected

## Key Considerations

### Legal & Ethical Constraints
- All tools are educational/authorized testing only
- Legal notice centralized in main README (required reading)
- Users must acknowledge responsibility before using
- Never add tools for destructive purposes (DoS, destruction, data theft)

### Portfolio Quality for Mid-Level Positions
- **Diversity matters:** Multiple attack vectors (web, network, system)
- **Depth matters:** Detailed technical explanations, not just working code
- **Professionalism matters:** Clean code, good docs, clear structure
- **Maturity matters:** Legal disclaimers, proper error handling, tested code

### Current Roadmap
Future tools to implement (prioritized for portfolio):
1. SQL injection enumeration (demonstrates web app expertise)
2. LDAP/Active Directory enumeration (demonstrates network/AD knowledge)
3. Post-exploitation utility (privilege escalation or persistence)
4. Simple C2 communication framework (demonstrates system-level understanding)

## Common Tasks

### Add a New Tool
1. Create subdirectory: `mkdir web-apps/NewAttack` or similar
2. Write script with full CLI argument parsing
3. Create `Readme.md` with technical documentation
4. Add dependencies to `requirements.txt` (if needed)
5. Commit with descriptive message

### Update requirements.txt
```bash
# Add new dependency
echo "new-package>=1.0.0" >> requirements.txt
# Commit it
git add requirements.txt
git commit -m "Add [package] dependency for [tool]"
```

### Verify Script Quality
- Run help: `python tool.py -h` → should show all options clearly
- Check code: No hardcoded targets, credentials, or endpoints
- Verify imports: `python -c "import requests"` → dependencies available
- Test error handling: Run with invalid args and timeouts

## Repository Standards

### Git Configuration (Local)
- User: `Pentesting-tech` (local to this repo)
- Email: `vhsoftwareba@gmail.com`
- Configuration already set: `git config --local user.name "Pentesting-tech"`

### Documentation Style
- No emojis/icons in documentation
- Plain markdown for maximum compatibility
- Clear, professional tone
- Avoid redundancy (license only in main README)

### Naming Conventions
- Python files: `lowercase-with-hyphens.py` (not snake_case for file names)
- Functions/variables: `snake_case`
- Classes: `PascalCase`
- Scripts should be self-documenting (use `argparse` help extensively)

## References

- **PortSwigger Web Security Academy:** Referenced in tool documentation for vulnerability context
- **Existing Tools:** Model new tools after `NoSQL-SSJI-time-based-blind.py` (structure, CLI, documentation)
- **Main README:** Always current source of truth for repo purpose, legal notice, quick start
