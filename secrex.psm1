Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Version = '0.2.0'

$script:Platform =
    if ($PSVersionTable.PSEdition -eq 'Desktop') { 'win' }
    elseif ($IsWindows) { 'win' }
    elseif ($IsMacOS)   { 'mac' }
    else                { 'linux' }

$script:BaseDir =
    if ($env:SECREX_HOME) { $env:SECREX_HOME }
    elseif ($script:Platform -eq 'win') { Join-Path $env:APPDATA 'secrex' }
    else {
        $cfg = if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path $HOME '.config' }
        Join-Path $cfg 'secrex'
    }

$script:StorePath   = Join-Path $script:BaseDir 'store.json'
$script:VaultTicket = $false

# glyphs, with plain-ASCII fallback for legacy conhost
$script:Fancy = ($script:Platform -ne 'win') -or [bool]$env:WT_SESSION
$script:G = @{
    Check = [string][char]0x2713
    Dash  = [string][char]0x2500
    Dot   = [string][char]0x00B7
    Spark = if ($script:Fancy) { ' ' + [char]::ConvertFromUtf32(0x2728) } else { '' }
    Lock  = if ($script:Fancy) { [char]::ConvertFromUtf32(0x1F512) } else { '' }
    Key   = if ($script:Fancy) { [char]::ConvertFromUtf32(0x1F510) } else { '' }
}

function ConvertTo-SxHashtable($obj) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [hashtable]) { return $obj }
    if ($obj -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in $obj.Keys) { $h[$k] = ConvertTo-SxHashtable $obj[$k] }
        return $h
    }
    if ($obj -is [array] -or ($obj -is [System.Collections.IList] -and -not ($obj -is [string]))) {
        return ,@($obj | ForEach-Object { ConvertTo-SxHashtable $_ })
    }
    if ($obj.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
        $h = @{}
        foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = ConvertTo-SxHashtable $p.Value }
        return $h
    }
    return $obj
}

function Get-SxStore {
    if (-not (Test-Path -LiteralPath $script:StorePath)) {
        return @{ projects = @{}; secrets = @{ '~' = @{} } }
    }
    $raw = Get-Content -LiteralPath $script:StorePath -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @{ projects = @{}; secrets = @{ '~' = @{} } }
    }
    $store = ConvertTo-SxHashtable ($raw | ConvertFrom-Json)
    if (-not $store.ContainsKey('projects')) { $store.projects = @{} }
    if (-not $store.ContainsKey('secrets'))  { $store.secrets  = @{} }
    if (-not $store.secrets.ContainsKey('~')) { $store.secrets['~'] = @{} }
    return $store
}

function Save-SxStore($store) {
    $dir = Split-Path -Parent $script:StorePath
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        if ($script:Platform -ne 'win') { & chmod 700 $dir 2>$null }
    }
    ($store | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $script:StorePath -Encoding UTF8
    if ($script:Platform -ne 'win') { & chmod 600 $script:StorePath 2>$null }
}

# --- encryption backends -----------------------------------------------------
# win   : DPAPI via ConvertFrom-SecureString (token = raw DPAPI ciphertext)
# mac   : login Keychain (token = 'keychain:1', value lives in Keychain)
# vault : macOS Keychain behind a Touch ID gate (token = 'vault:1')
# linux : AES via ConvertFrom-SecureString -Key, key file chmod 600 (token = 'aes:...')

function ConvertFrom-SxSecure([SecureString]$Secure) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        # PtrToStringAuto misreads BSTR (UTF-16) as UTF-8 on macOS/Linux and
        # truncates at the first interleaved null byte; PtrToStringBSTR is
        # correct on every platform.
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-SxFileKey {
    $keyPath = Join-Path $script:BaseDir 'key'
    if (Test-Path -LiteralPath $keyPath) {
        return [Convert]::FromBase64String((Get-Content -LiteralPath $keyPath -Raw).Trim())
    }
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $dir = Split-Path -Parent $keyPath
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        if ($script:Platform -ne 'win') { & chmod 700 $dir 2>$null }
    }
    [Convert]::ToBase64String($bytes) | Set-Content -LiteralPath $keyPath -Encoding ASCII
    if ($script:Platform -ne 'win') { & chmod 600 $keyPath 2>$null }
    return $bytes
}

# values are stored base64-encoded: `security ... -w` dumps passwords with
# non-printable characters (e.g. newlines) as a hex blob, base64 keeps the
# round-trip lossless
function Set-SxKeychainValue([string]$Service, [string]$Account, [string]$Value) {
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value))
    & security add-generic-password -U -s $Service -a $Account -w $b64 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Keychain write failed for '$Account'" }
}

function Get-SxKeychainValue([string]$Service, [string]$Account) {
    $out = & security find-generic-password -s $Service -a $Account -w 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Not found in Keychain: $Account" }
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((@($out) -join '')))
}

function Remove-SxKeychainValue([string]$Service, [string]$Account) {
    & security delete-generic-password -s $Service -a $Account 2>&1 | Out-Null
}

function Invoke-SxBioAuth([string]$Reason) {
    $js = @'
ObjC.import("LocalAuthentication");
function run(argv) {
    var reason = argv[0] || "unlock the secrex vault";
    var ctx = $.LAContext.alloc.init;
    var err = Ref();
    var policy = $.LAPolicyDeviceOwnerAuthenticationWithBiometrics;
    if (!ctx.canEvaluatePolicyError(policy, err)) {
        policy = $.LAPolicyDeviceOwnerAuthentication;
        if (!ctx.canEvaluatePolicyError(policy, err)) { return "unavailable"; }
    }
    var done = false, ok = false;
    ctx.evaluatePolicyLocalizedReasonReply(policy, reason, function (success, error) {
        ok = !!success;
        done = true;
    });
    var deadline = $.NSDate.dateWithTimeIntervalSinceNow(120);
    while (!done && $.NSDate.date.compare(deadline) === $.NSOrderedAscending) {
        $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.1));
    }
    if (!done) { ctx.invalidate; return "timeout"; }
    return ok ? "ok" : "denied";
}
'@
    $res = & osascript -l JavaScript -e $js $Reason 2>$null
    return ($res -eq 'ok')
}

function Assert-SxVaultAccess([string]$Reason) {
    if ($script:Platform -ne 'mac') {
        throw "The 'vault' scope needs macOS (Touch ID). Use ~ or a project scope here."
    }
    if ($script:VaultTicket) { return }
    if (-not (Invoke-SxBioAuth $Reason)) {
        throw "vault: authentication cancelled or failed"
    }
    $script:VaultTicket = $true
}

function Protect-SxSecure([SecureString]$Secure, [string]$Scope, [string]$Name) {
    if ($Scope -eq 'vault') {
        Assert-SxVaultAccess "add '$Name' to the secrex vault"
        Set-SxKeychainValue 'secrex.vault' $Name (ConvertFrom-SxSecure $Secure)
        return 'vault:1'
    }
    switch ($script:Platform) {
        'win' { return ConvertFrom-SecureString $Secure }
        'mac' {
            Set-SxKeychainValue 'secrex' "$Scope/$Name" (ConvertFrom-SxSecure $Secure)
            return 'keychain:1'
        }
        default { return 'aes:' + (ConvertFrom-SecureString $Secure -Key (Get-SxFileKey)) }
    }
}

function Unprotect-SxToken([string]$Token, [string]$Scope, [string]$Name) {
    if ($Token -eq 'vault:1') {
        Assert-SxVaultAccess "read 'vault/$Name'"
        return Get-SxKeychainValue 'secrex.vault' $Name
    }
    if ($Token -eq 'keychain:1') {
        return Get-SxKeychainValue 'secrex' "$Scope/$Name"
    }
    if ($Token.StartsWith('aes:')) {
        $secure = ConvertTo-SecureString $Token.Substring(4) -Key (Get-SxFileKey)
        return ConvertFrom-SxSecure $secure
    }
    # legacy token without prefix: Windows DPAPI
    if ($script:Platform -ne 'win') {
        throw "Secret '$Scope/$Name' was written with Windows DPAPI and can only be read on the Windows account that created it."
    }
    return ConvertFrom-SxSecure (ConvertTo-SecureString $Token)
}

function Remove-SxSecretEntry($store, [string]$Scope, [string]$Name) {
    $token = $store.secrets[$Scope][$Name]
    if ($token -eq 'keychain:1') { Remove-SxKeychainValue 'secrex' "$Scope/$Name" }
    elseif ($token -eq 'vault:1') { Remove-SxKeychainValue 'secrex.vault' $Name }
    $store.secrets[$Scope].Remove($Name)
    if ($Scope -eq 'vault' -and $store.secrets[$Scope].Count -eq 0) {
        $store.secrets.Remove($Scope)
    }
    Save-SxStore $store
}

# --- path grammar ------------------------------------------------------------

function Split-SxPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "Path is empty" }
    if ($Path -eq '~')           { throw "Specify secret name, e.g. ~/openai" }
    if ($Path.EndsWith('/'))     { throw "Specify secret name, e.g. $Path" + "openai" }
    if ($Path.StartsWith('/'))   { throw "Specify scope, e.g. ~$Path or myapp$Path" }

    if ($Path -notmatch '/') {
        return @{ scope = '~'; name = $Path }
    }
    $parts = $Path -split '/', 2
    $scope = if ($parts[0] -eq '~') { '~' } else { $parts[0] }
    $name  = $parts[1]
    if ([string]::IsNullOrWhiteSpace($name))  { throw "Secret name missing in '$Path'" }
    if ([string]::IsNullOrWhiteSpace($scope)) { throw "Scope missing in '$Path'" }
    return @{ scope = $scope; name = $name }
}

function Format-SxPath($scope, $name) {
    if ($scope -eq '~') { return "~/$name" }
    return "$scope/$name"
}

function Split-SxPattern([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "Pattern is empty" }
    if ($Path -eq '~')       { throw "Specify secret name, e.g. ~/openai" }
    if ($Path.EndsWith('/')) { throw "Secret name missing after '/'" }
    if ($Path -notmatch '/') {
        return @{ scope = '~'; name = $Path }
    }
    $parts = $Path -split '/', 2
    $scope = if ($parts[0] -eq '') { '*' } else { $parts[0] }
    $name  = $parts[1]
    if ([string]::IsNullOrWhiteSpace($name)) { throw "Secret name missing in '$Path'" }
    return @{ scope = $scope; name = $name }
}

# --- commands ----------------------------------------------------------------

function Invoke-SxSet {
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [Parameter(Position = 1)][AllowEmptyString()][string]$Value
    )
    $p = Split-SxPath $Path
    $store = Get-SxStore
    if ($p.scope -notin @('~', 'vault') -and -not $store.projects.ContainsKey($p.scope)) {
        throw "Project '$($p.scope)' is not registered. cd into its folder and run: secrex init"
    }
    if ($PSBoundParameters.ContainsKey('Value')) {
        if ([string]::IsNullOrEmpty($Value)) { throw "Empty value" }
        $secure = ConvertTo-SecureString $Value -AsPlainText -Force
    } else {
        $secure = Read-Host -Prompt "value for $(Format-SxPath $p.scope $p.name)" -AsSecureString
        if ($secure.Length -eq 0) { throw "Empty value" }
    }
    if (-not $store.secrets.ContainsKey($p.scope)) { $store.secrets[$p.scope] = @{} }
    $store.secrets[$p.scope][$p.name] = Protect-SxSecure $secure $p.scope $p.name
    Save-SxStore $store
    Write-Host "saved: $(Format-SxPath $p.scope $p.name)"
}

function Invoke-SxGet {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AsSecureString,
        [switch]$Copy
    )
    $p = Split-SxPattern $Path
    $store = Get-SxStore

    $found = @()
    foreach ($scope in $store.secrets.Keys) {
        if ($scope -notlike $p.scope) { continue }
        foreach ($name in $store.secrets[$scope].Keys) {
            if ($name -notlike $p.name) { continue }
            $found += [pscustomobject]@{
                Scope = $scope
                Name  = $name
                Enc   = $store.secrets[$scope][$name]
            }
        }
    }

    if ($found.Count -eq 0) { throw "Not found: $Path" }

    $isWildcard = ($p.scope -match '[\*\?\[]') -or ($p.name -match '[\*\?\[]')

    if (-not $isWildcard -and $found.Count -eq 1) {
        $m = $found[0]
        $plain = Unprotect-SxToken $m.Enc $m.Scope $m.Name
        if ($AsSecureString) { return ConvertTo-SecureString $plain -AsPlainText -Force }
        if ($Copy) {
            Set-Clipboard -Value $plain
            Write-Host "copied: $(Format-SxPath $m.Scope $m.Name)"
            return
        }
        return $plain
    }

    if ($Copy)           { throw "-Copy requires an exact match (pattern '$Path' matched $($found.Count))" }
    if ($AsSecureString) { throw "-AsSecureString requires an exact match (pattern '$Path' matched $($found.Count))" }

    return @($found | Sort-Object Scope, Name | ForEach-Object {
        [pscustomobject]@{
            Path  = Format-SxPath $_.Scope $_.Name
            Value = Unprotect-SxToken $_.Enc $_.Scope $_.Name
        }
    })
}

function Invoke-SxRemove {
    param([Parameter(Mandatory)][string]$Path)
    $p = Split-SxPath $Path
    $store = Get-SxStore
    if (-not $store.secrets.ContainsKey($p.scope) -or -not $store.secrets[$p.scope].ContainsKey($p.name)) {
        throw "Not found: $(Format-SxPath $p.scope $p.name)"
    }
    Remove-SxSecretEntry $store $p.scope $p.name
    Write-Host "removed: $(Format-SxPath $p.scope $p.name)"
}

function Invoke-SxList {
    param([string]$Filter)
    $store = Get-SxStore

    if (-not $Filter) {
        $out = @()
        foreach ($scope in ($store.secrets.Keys | Sort-Object)) {
            foreach ($name in ($store.secrets[$scope].Keys | Sort-Object)) {
                $out += Format-SxPath $scope $name
            }
        }
        return $out
    }

    if ($Filter -eq '~') {
        return @($store.secrets['~'].Keys | Sort-Object | ForEach-Object { "~/$_" })
    }

    if ($Filter -eq 'projects') {
        return @($store.projects.Keys | Sort-Object | ForEach-Object {
            [pscustomobject]@{ Name = $_; Path = $store.projects[$_].path }
        })
    }

    if ($Filter.StartsWith('/')) {
        $name = $Filter.Substring(1)
        if (-not $name) { throw "Name missing after '/'" }
        $out = @()
        foreach ($scope in ($store.secrets.Keys | Sort-Object)) {
            if ($store.secrets[$scope].ContainsKey($name)) {
                $out += Format-SxPath $scope $name
            }
        }
        return $out
    }

    $scope = $Filter.TrimEnd('/')
    if (-not $store.secrets.ContainsKey($scope)) {
        throw "No secrets in scope '$scope'"
    }
    return @($store.secrets[$scope].Keys | Sort-Object | ForEach-Object { Format-SxPath $scope $_ })
}

function Invoke-SxInit {
    param([switch]$Force)
    $cwd  = (Get-Location).Path
    $name = Split-Path -Leaf $cwd
    if ($name -in @('~', 'projects', 'vault')) {
        throw "'$name' is a reserved scope name; rename the folder or register it differently."
    }
    $store = Get-SxStore
    if ($store.projects.ContainsKey($name) -and -not $Force) {
        $existing = $store.projects[$name].path
        if ($existing -ne $cwd) {
            throw "Project '$name' already registered at '$existing'. Use -Force to overwrite."
        }
        Write-Host "already registered: $name -> $cwd"
        return
    }
    $store.projects[$name] = @{ path = $cwd }
    if (-not $store.secrets.ContainsKey($name)) { $store.secrets[$name] = @{} }
    Save-SxStore $store
    Write-Host "registered: $name -> $cwd"
}

# --- .env import / export ----------------------------------------------------

function Invoke-SxImport {
    param(
        [Parameter(Mandatory, Position = 0)][string]$File,
        [Parameter(Position = 1)][string]$Scope = '~'
    )
    if (-not (Test-Path -LiteralPath $File)) { throw "File not found: $File" }
    $Scope = $Scope.TrimEnd('/')
    $store = Get-SxStore
    if ($Scope -notin @('~', 'vault') -and -not $store.projects.ContainsKey($Scope)) {
        throw "Project '$Scope' is not registered. cd into its folder and run: secrex init"
    }

    $count = 0
    $skipped = @()
    foreach ($rawLine in @(Get-Content -LiteralPath $File -Encoding UTF8)) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $line = $line -replace '^export\s+', ''
        if ($line -notmatch '^([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*)$') {
            $skipped += $rawLine.Trim()
            continue
        }
        $key = $Matches[1]
        $val = $Matches[2].Trim()
        if ($val.Length -ge 2 -and $val[0] -eq '"' -and $val[-1] -eq '"') {
            $val = $val.Substring(1, $val.Length - 2)
            $val = $val.Replace('\\', [string][char]1).Replace('\n', "`n").Replace('\r', "`r").Replace('\t', "`t").Replace('\"', '"').Replace([string][char]1, '\')
        } elseif ($val.Length -ge 2 -and $val[0] -eq "'" -and $val[-1] -eq "'") {
            $val = $val.Substring(1, $val.Length - 2)
        } else {
            $val = ($val -replace '\s+#.*$', '').Trim()
        }
        if (-not $val) { $skipped += "$key (empty value)"; continue }
        $secure = ConvertTo-SecureString $val -AsPlainText -Force
        if (-not $store.secrets.ContainsKey($Scope)) { $store.secrets[$Scope] = @{} }
        $store.secrets[$Scope][$key] = Protect-SxSecure $secure $Scope $key
        $count++
    }
    Save-SxStore $store
    Write-Host "imported $count secret(s) into '$Scope' from $File"
    foreach ($s in $skipped) { Write-Host "  skipped: $s" -ForegroundColor DarkYellow }
}

function Invoke-SxExport {
    param(
        [Parameter(Position = 0)][string]$Scope = '~',
        [Parameter(Position = 1)][string]$File
    )
    $Scope = $Scope.TrimEnd('/')
    $store = Get-SxStore
    if (-not $store.secrets.ContainsKey($Scope) -or $store.secrets[$Scope].Count -eq 0) {
        throw "No secrets in scope '$Scope'"
    }
    $lines = @()
    foreach ($name in ($store.secrets[$Scope].Keys | Sort-Object)) {
        $v = Unprotect-SxToken $store.secrets[$Scope][$name] $Scope $name
        if ($v -match '[\s"#\\]' -or $v.Contains("'") -or $v.Contains("`n")) {
            $v = '"' + $v.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n') + '"'
        }
        $lines += "$name=$v"
    }
    if ($File) {
        ($lines -join "`n") + "`n" | Set-Content -LiteralPath $File -Encoding UTF8 -NoNewline
        if ($script:Platform -ne 'win') { & chmod 600 $File 2>$null }
        Write-Host "exported $($lines.Count) secret(s) from '$Scope' to $File" -NoNewline
        Write-Host '  (plaintext -- handle with care)' -ForegroundColor DarkYellow
        return
    }
    return $lines
}

# --- TUI ---------------------------------------------------------------------

function Format-SxCell([string]$s, [int]$w) {
    if ($null -eq $s) { $s = '' }
    if ($s.Length -ge $w) { return $s.Substring(0, $w) }
    return $s + (' ' * ($w - $s.Length))
}

function Write-SxRow($leftText, $rightText, $colW, $leftHl, $rightHl, $activeLeft, $activeRight, $leftColor, $rightColor) {
    if (-not $leftColor)  { $leftColor  = 'Gray' }
    if (-not $rightColor) { $rightColor = 'Gray' }
    Write-Host '|' -NoNewline -ForegroundColor DarkGray
    if ($leftHl -and $activeLeft) {
        Write-Host (Format-SxCell $leftText $colW) -NoNewline -ForegroundColor Black -BackgroundColor Cyan
    } elseif ($leftHl) {
        Write-Host (Format-SxCell $leftText $colW) -NoNewline -ForegroundColor Cyan
    } else {
        Write-Host (Format-SxCell $leftText $colW) -NoNewline -ForegroundColor $leftColor
    }
    Write-Host '|' -NoNewline -ForegroundColor DarkGray
    if ($rightHl -and $activeRight) {
        Write-Host (Format-SxCell $rightText $colW) -NoNewline -ForegroundColor Black -BackgroundColor Cyan
    } elseif ($rightHl) {
        Write-Host (Format-SxCell $rightText $colW) -NoNewline -ForegroundColor Cyan
    } else {
        Write-Host (Format-SxCell $rightText $colW) -NoNewline -ForegroundColor $rightColor
    }
    Write-Host '|' -ForegroundColor DarkGray
}

function Write-SxHint([string[]]$Pairs) {
    Write-Host ''
    Write-Host '  ' -NoNewline
    for ($i = 0; $i -lt $Pairs.Count; $i += 2) {
        Write-Host $Pairs[$i] -NoNewline -ForegroundColor Yellow
        Write-Host (' ' + $Pairs[$i + 1] + '  ') -NoNewline -ForegroundColor DarkGray
    }
    Write-Host ''
}

function Show-SxIntro {
    if ($env:SECREX_NO_ANIM -eq '1' -or $env:SECREX_TUI_DRYRUN -eq '1') { return }
    $word   = 'secrex'
    $shades = @('DarkCyan', 'Cyan', 'Cyan', 'Magenta', 'Magenta', 'DarkMagenta')
    Clear-Host
    Write-Host ''
    Write-Host ''
    Write-Host '   ' -NoNewline
    for ($i = 0; $i -lt $word.Length; $i++) {
        Write-Host $word[$i] -NoNewline -ForegroundColor $shades[$i]
        Start-Sleep -Milliseconds 42
    }
    if ($script:G.Key) { Write-Host ('  ' + $script:G.Key) -NoNewline }
    Write-Host ''
    Write-Host '   ' -NoNewline
    for ($i = 0; $i -lt 8; $i++) {
        Write-Host $script:G.Dash -NoNewline -ForegroundColor DarkMagenta
        Start-Sleep -Milliseconds 24
    }
    Write-Host ''
    Start-Sleep -Milliseconds 160
}

function Invoke-SxTui {
    if ($env:SECREX_TUI_DRYRUN -ne '1') {
        try {
            [void][Console]::WindowWidth
        } catch {
            Show-SxHelp
            return
        }
    }

    $prevEncoding = [Console]::OutputEncoding
    $prevCursor   = $true
    try { $prevCursor = [Console]::CursorVisible } catch {}
    try {
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new()
        try { [Console]::CursorVisible = $false } catch {}

        Show-SxIntro

        $state = [ordered]@{
            Screen      = 'root'
            Pane        = 0
            SelPersonal = 0
            SelProject  = 0
            SelInProj   = 0
            Project     = ''
            Flash       = ''
            FlashColor  = 'Green'
            Confirm     = ''
        }

        while ($true) {
            $script:VaultTicket = $false
            $store    = Get-SxStore
            $personal = @($store.secrets['~'].Keys | Sort-Object)
            $projects = @($store.projects.Keys    | Sort-Object)
            # on macOS the Touch ID vault is pinned on top of the right pane
            $projRows = @(if ($script:Platform -eq 'mac') { @('vault') + $projects } else { $projects })

            if ($state.SelPersonal -ge $personal.Count) { $state.SelPersonal = [Math]::Max(0, $personal.Count - 1) }
            if ($state.SelProject  -ge $projRows.Count) { $state.SelProject  = [Math]::Max(0, $projRows.Count - 1) }

            $w = 80
            try { $w = [Console]::WindowWidth } catch {}
            if ($w -lt 50) { $w = 50 }
            $colW = [Math]::Floor(($w - 3) / 2)

            Clear-Host

            Write-Host ''
            Write-Host '  secrex' -NoNewline -ForegroundColor Magenta
            Write-Host (' v' + $script:Version) -NoNewline -ForegroundColor DarkGray
            Write-Host ('   ' + $personal.Count + ' personal ' + $script:G.Dot + ' ' + $projects.Count + ' projects') -ForegroundColor DarkGray
            Write-Host ''

            if ($state.Screen -eq 'root') {
                $leftHdr  = ' personal'
                $rightHdr = ' projects'
                Write-Host ('+' + ('-' * $colW) + '+' + ('-' * $colW) + '+') -ForegroundColor DarkGray

                Write-Host '|' -NoNewline -ForegroundColor DarkGray
                if ($state.Pane -eq 0) {
                    Write-Host (Format-SxCell $leftHdr $colW) -NoNewline -ForegroundColor Yellow
                } else {
                    Write-Host (Format-SxCell $leftHdr $colW) -NoNewline -ForegroundColor DarkGray
                }
                Write-Host '|' -NoNewline -ForegroundColor DarkGray
                if ($state.Pane -eq 1) {
                    Write-Host (Format-SxCell $rightHdr $colW) -NoNewline -ForegroundColor Yellow
                } else {
                    Write-Host (Format-SxCell $rightHdr $colW) -NoNewline -ForegroundColor DarkGray
                }
                Write-Host '|' -ForegroundColor DarkGray

                Write-Host ('+' + ('-' * $colW) + '+' + ('-' * $colW) + '+') -ForegroundColor DarkGray

                $rows = [Math]::Max($personal.Count, $projRows.Count)
                if ($rows -eq 0) { $rows = 1 }
                for ($i = 0; $i -lt $rows; $i++) {
                    $lText = ''
                    if ($i -lt $personal.Count) {
                        $lText = '  ' + $personal[$i]
                    } elseif ($personal.Count -eq 0 -and $i -eq 0) {
                        $lText = '  (empty)'
                    }
                    $rText = ''
                    $rColor = 'Gray'
                    if ($i -lt $projRows.Count) {
                        if ($projRows[$i] -eq 'vault' -and $script:Platform -eq 'mac') {
                            $rText  = '  vault ' + $script:G.Lock
                            $rColor = 'Magenta'
                        } else {
                            $rText = '  ' + $projRows[$i]
                        }
                    } elseif ($projRows.Count -eq 0 -and $i -eq 0) {
                        $rText = '  (empty)'
                    }
                    $lHl = ($i -eq $state.SelPersonal) -and ($personal.Count -gt 0)
                    $rHl = ($i -eq $state.SelProject)  -and ($projRows.Count -gt 0)
                    Write-SxRow $lText $rText $colW $lHl $rHl ($state.Pane -eq 0) ($state.Pane -eq 1) 'Gray' $rColor
                }
                Write-Host ('+' + ('-' * $colW) + '+' + ('-' * $colW) + '+') -ForegroundColor DarkGray

                Write-SxHint @('up/dn', 'nav', 'Tab', 'switch', 'Enter', 'open/copy', 'p', 'peek', 'a', 'add', 'd', 'del', 'q', 'quit')
            }
            else {
                $secrets = @()
                if ($store.secrets.ContainsKey($state.Project)) {
                    $secrets = @($store.secrets[$state.Project].Keys | Sort-Object)
                }
                if ($state.SelInProj -ge $secrets.Count) { $state.SelInProj = [Math]::Max(0, $secrets.Count - 1) }

                $fullW = ($colW * 2) + 1
                $hdr = " $($state.Project)"
                if ($state.Project -eq 'vault') { $hdr = ' vault ' + $script:G.Lock + '  (Touch ID)' }
                Write-Host ('+' + ('-' * $fullW) + '+') -ForegroundColor DarkGray
                Write-Host '|' -NoNewline -ForegroundColor DarkGray
                Write-Host (Format-SxCell $hdr $fullW) -NoNewline -ForegroundColor Yellow
                Write-Host '|' -ForegroundColor DarkGray
                Write-Host ('+' + ('-' * $fullW) + '+') -ForegroundColor DarkGray

                $rows = if ($secrets.Count -gt 0) { $secrets.Count } else { 1 }
                for ($i = 0; $i -lt $rows; $i++) {
                    Write-Host '|' -NoNewline -ForegroundColor DarkGray
                    if ($secrets.Count -eq 0) {
                        Write-Host (Format-SxCell '  (empty)' $fullW) -NoNewline -ForegroundColor DarkGray
                    } else {
                        $text = "  $($secrets[$i])"
                        if ($i -eq $state.SelInProj) {
                            Write-Host (Format-SxCell $text $fullW) -NoNewline -ForegroundColor Black -BackgroundColor Cyan
                        } else {
                            Write-Host (Format-SxCell $text $fullW) -NoNewline -ForegroundColor Gray
                        }
                    }
                    Write-Host '|' -ForegroundColor DarkGray
                }
                Write-Host ('+' + ('-' * $fullW) + '+') -ForegroundColor DarkGray

                Write-SxHint @('up/dn', 'nav', 'Enter', 'copy', 'p', 'peek', 'a', 'add', 'd', 'del', 'Esc', 'back', 'q', 'quit')
            }

            if ($state.Confirm) {
                Write-Host ''
                Write-Host "  delete $($state.Confirm)? " -NoNewline -ForegroundColor Red
                Write-Host 'y/n' -ForegroundColor Yellow
            }
            elseif ($state.Flash) {
                Write-Host ''
                Write-Host "  $($state.Flash)" -ForegroundColor $state.FlashColor
                $state.Flash = ''
            }

            if ($env:SECREX_TUI_DRYRUN -eq '1') { return }
            $key = [Console]::ReadKey($true)

            # figure out what is currently selected (scope + name), shared by copy/peek/del
            $selScope = $null
            $selName  = $null
            if ($state.Screen -eq 'root') {
                if ($state.Pane -eq 0 -and $personal.Count -gt 0) {
                    $selScope = '~'; $selName = $personal[$state.SelPersonal]
                }
            } else {
                $pSecrets = @()
                if ($store.secrets.ContainsKey($state.Project)) {
                    $pSecrets = @($store.secrets[$state.Project].Keys | Sort-Object)
                }
                if ($pSecrets.Count -gt 0) {
                    $selScope = $state.Project; $selName = $pSecrets[$state.SelInProj]
                }
            }

            if ($state.Confirm) {
                if ($key.Key -eq 'Y') {
                    try {
                        $p = Split-SxPath $state.Confirm
                        Remove-SxSecretEntry $store $p.scope $p.name
                        $state.Flash = "removed: $($state.Confirm)"
                        $state.FlashColor = 'Yellow'
                    } catch {
                        $state.Flash = $_.Exception.Message
                        $state.FlashColor = 'Red'
                    }
                }
                $state.Confirm = ''
                continue
            }

            # keys shared by both screens
            $handled = $true
            switch ($key.Key) {
                'Q' { return }
                'P' {
                    if ($selScope) {
                        try {
                            $plain = Unprotect-SxToken $store.secrets[$selScope][$selName] $selScope $selName
                            $max = $w - $selName.Length - 12
                            if ($plain.Length -gt $max) { $plain = $plain.Substring(0, [Math]::Max(1, $max)) + '...' }
                            $state.Flash = "$selName $($script:G.Dot) $plain"
                            $state.FlashColor = 'Yellow'
                        } catch {
                            $state.Flash = $_.Exception.Message
                            $state.FlashColor = 'Red'
                        }
                    }
                }
                'D' {
                    if ($selScope) { $state.Confirm = Format-SxPath $selScope $selName }
                }
                'A' {
                    $scope = '~'
                    if ($state.Screen -eq 'project') { $scope = $state.Project }
                    elseif ($state.Pane -eq 1) {
                        if ($projRows.Count -gt 0) { $scope = $projRows[$state.SelProject] }
                        else { $state.Flash = 'no project selected'; $state.FlashColor = 'Yellow'; break }
                    }
                    try { [Console]::CursorVisible = $true } catch {}
                    Write-Host ''
                    $name = Read-Host "  new secret name ($scope/...)"
                    if ([string]::IsNullOrWhiteSpace($name)) {
                        $state.Flash = 'cancelled'
                        $state.FlashColor = 'Yellow'
                    } else {
                        try {
                            Invoke-SxSet "$scope/$name"
                            $state.Flash = "$($script:G.Check) saved: $(Format-SxPath $scope $name)$($script:G.Spark)"
                            $state.FlashColor = 'Green'
                        } catch {
                            $state.Flash = $_.Exception.Message
                            $state.FlashColor = 'Red'
                        }
                    }
                    try { [Console]::CursorVisible = $false } catch {}
                }
                default { $handled = $false }
            }
            if ($handled) { continue }

            if ($state.Screen -eq 'root') {
                switch ($key.Key) {
                    'Escape'     { return }
                    'Tab'        { $state.Pane = 1 - $state.Pane }
                    'LeftArrow'  { $state.Pane = 0 }
                    'RightArrow' { $state.Pane = 1 }
                    'UpArrow' {
                        if ($state.Pane -eq 0 -and $state.SelPersonal -gt 0) { $state.SelPersonal-- }
                        elseif ($state.Pane -eq 1 -and $state.SelProject -gt 0) { $state.SelProject-- }
                    }
                    'DownArrow' {
                        if ($state.Pane -eq 0 -and $state.SelPersonal -lt $personal.Count - 1) { $state.SelPersonal++ }
                        elseif ($state.Pane -eq 1 -and $state.SelProject -lt $projRows.Count - 1) { $state.SelProject++ }
                    }
                    'Enter' {
                        if ($state.Pane -eq 0 -and $personal.Count -gt 0) {
                            try {
                                $name = $personal[$state.SelPersonal]
                                $plain = Unprotect-SxToken $store.secrets['~'][$name] '~' $name
                                Set-Clipboard -Value $plain
                                $state.Flash = "$($script:G.Check) copied: ~/$name$($script:G.Spark)"
                                $state.FlashColor = 'Green'
                            } catch {
                                $state.Flash = $_.Exception.Message
                                $state.FlashColor = 'Red'
                            }
                        }
                        elseif ($state.Pane -eq 1 -and $projRows.Count -gt 0) {
                            $state.Project   = $projRows[$state.SelProject]
                            $state.Screen    = 'project'
                            $state.SelInProj = 0
                        }
                    }
                }
            }
            else {
                switch ($key.Key) {
                    'Escape'    { $state.Screen = 'root' }
                    'Backspace' { $state.Screen = 'root' }
                    'LeftArrow' { $state.Screen = 'root' }
                    'UpArrow'   { if ($state.SelInProj -gt 0) { $state.SelInProj-- } }
                    'DownArrow' {
                        $pSecrets = @()
                        if ($store.secrets.ContainsKey($state.Project)) {
                            $pSecrets = @($store.secrets[$state.Project].Keys)
                        }
                        if ($state.SelInProj -lt $pSecrets.Count - 1) { $state.SelInProj++ }
                    }
                    'Enter' {
                        if ($selScope) {
                            try {
                                $plain = Unprotect-SxToken $store.secrets[$selScope][$selName] $selScope $selName
                                Set-Clipboard -Value $plain
                                $state.Flash = "$($script:G.Check) copied: $(Format-SxPath $selScope $selName)$($script:G.Spark)"
                                $state.FlashColor = 'Green'
                            } catch {
                                $state.Flash = $_.Exception.Message
                                $state.FlashColor = 'Red'
                            }
                        }
                    }
                }
            }
        }
    } finally {
        try { [Console]::CursorVisible = $prevCursor } catch {}
        [Console]::OutputEncoding = $prevEncoding
        if ($env:SECREX_TUI_DRYRUN -ne '1') { Clear-Host }
    }
}

function Show-SxHelp {
    @"
secrex v$($script:Version) -- per-user secret manager ($script:StorePath)

Encryption: Windows DPAPI / macOS Keychain / Linux AES key file.
On macOS the reserved 'vault' scope is additionally gated by Touch ID.

Commands:
  init   | i                register current folder as a project
  set    | s | add | a <path> [value]  store secret (prompts if no value)
  get    | g   <path>       print secret     [-AsSecureString] [-Copy]
  list   | ls  [filter]     list secrets
  remove | rm  <path>       delete secret
  import <file> [scope]     import KEY=VALUE pairs from a .env file
  export [scope] [file]     export scope as .env (stdout if no file)
  version                   print version

Paths:
  openai              personal (same as ~/openai)
  ~/openai            personal, explicit
  myapp/openai        project myapp
  vault/prod-token    Touch ID vault (macOS only)

List filters:
  <empty>             everything
  ~                   all personal
  projects            registered projects
  myapp  | myapp/     all in project myapp
  /openai             all secrets named openai across scopes

Examples:
  # register current folder as a project (uses folder name)
  cd ~/dev/myapp
  secrex init

  # add a personal secret, interactive hidden prompt
  secrex add openai
  secrex add ~/openai

  # add a secret inside project myapp, interactive
  secrex add myapp/openai
  secrex a myapp/github

  # add with value inline (WARNING: goes into shell history)
  secrex add bright-data 1d045222

  # macOS: keep a secret behind Touch ID
  secrex add vault/prod-token
  secrex get vault/prod-token          # asks for your fingerprint

  # read an exact secret
  secrex get ~/openai
  secrex g  myapp/openai -Copy          # put value into clipboard
  `$sec = secrex g myapp/openai -AsSecureString

  # read by wildcard (returns Path+Value rows)
  secrex g 'bri*'                       # personal, names starting with 'bri'
  secrex g 'myapp/*'                    # everything in project myapp
  secrex g '/bright-data'               # 'bright-data' across all scopes

  # .env round-trip
  secrex import .env myapp              # .env lines -> myapp/KEY secrets
  secrex export myapp .env.local        # scope -> .env file (chmod 600)
  secrex export myapp                   # scope -> stdout

  # list / delete
  secrex ls
  secrex ls myapp
  secrex rm myapp/github

TUI: run 'secrex' with no arguments. Set SECREX_NO_ANIM=1 to skip the intro
animation, SECREX_HOME to relocate the store.
"@
}

function Split-SxArgs($argsArray) {
    $positional = @()
    $named = @{}
    for ($i = 0; $i -lt $argsArray.Count; $i++) {
        $item = $argsArray[$i]
        if ($item -is [string] -and $item.Length -gt 1 -and $item.StartsWith('-') -and $item -notmatch '^-\d') {
            $key = $item.Substring(1)
            $nextIsValue = ($i + 1 -lt $argsArray.Count) -and -not (
                $argsArray[$i+1] -is [string] -and
                $argsArray[$i+1].Length -gt 1 -and
                $argsArray[$i+1].StartsWith('-') -and
                $argsArray[$i+1] -notmatch '^-\d'
            )
            if ($nextIsValue) {
                $named[$key] = $argsArray[$i+1]
                $i++
            } else {
                $named[$key] = $true
            }
        } else {
            $positional += ,$item
        }
    }
    return @{ Positional = $positional; Named = $named }
}

function Invoke-Secrex {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$Command,
        [Parameter(Position = 1, ValueFromRemainingArguments = $true)]$Rest
    )
    if (-not $Rest) { $Rest = @() }
    $script:VaultTicket = $false
    if ([string]::IsNullOrEmpty($Command)) { Invoke-SxTui; return }
    switch ($Command) {
        'help'      { Show-SxHelp; return }
        '-h'        { Show-SxHelp; return }
        '--help'    { Show-SxHelp; return }
        'version'   { return "secrex v$($script:Version)" }
        '--version' { return "secrex v$($script:Version)" }
    }
    $handler = switch ($Command) {
        { $_ -in 'init','i' }             { 'Invoke-SxInit';   break }
        { $_ -in 'set','s','add','a' }    { 'Invoke-SxSet';    break }
        { $_ -in 'get','g' }              { 'Invoke-SxGet';    break }
        { $_ -in 'list','ls' }            { 'Invoke-SxList';   break }
        { $_ -in 'remove','rm' }          { 'Invoke-SxRemove'; break }
        { $_ -in 'import','imp' }         { 'Invoke-SxImport'; break }
        { $_ -in 'export','exp' }         { 'Invoke-SxExport'; break }
        default { throw "Unknown command: '$Command'. Run 'secrex help'." }
    }
    $split = Split-SxArgs $Rest
    $pos   = @($split.Positional)
    $named = $split.Named
    & $handler @pos @named
}

Set-Alias -Name secrex -Value Invoke-Secrex
Export-ModuleMember -Function Invoke-Secrex -Alias secrex
