Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:StorePath = Join-Path $env:APPDATA 'secrex\store.json'

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
    }
    ($store | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $script:StorePath -Encoding UTF8
}

function Unprotect-SxValue([string]$encrypted) {
    $secure = ConvertTo-SecureString $encrypted
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

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

function Invoke-SxSet {
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [Parameter(Position = 1)][AllowEmptyString()][string]$Value
    )
    $p = Split-SxPath $Path
    $store = Get-SxStore
    if ($p.scope -ne '~' -and -not $store.projects.ContainsKey($p.scope)) {
        throw "Project '$($p.scope)' is not registered. cd into its folder and run: secrex init"
    }
    if ($PSBoundParameters.ContainsKey('Value')) {
        if ([string]::IsNullOrEmpty($Value)) { throw "Empty value" }
        $encrypted = ConvertFrom-SecureString (ConvertTo-SecureString $Value -AsPlainText -Force)
    } else {
        $secure = Read-Host -Prompt "value for $(Format-SxPath $p.scope $p.name)" -AsSecureString
        if ($secure.Length -eq 0) { throw "Empty value" }
        $encrypted = ConvertFrom-SecureString $secure
    }
    if (-not $store.secrets.ContainsKey($p.scope)) { $store.secrets[$p.scope] = @{} }
    $store.secrets[$p.scope][$p.name] = $encrypted
    Save-SxStore $store
    Write-Host "saved: $(Format-SxPath $p.scope $p.name)"
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
        if ($AsSecureString) { return ConvertTo-SecureString $m.Enc }
        $plain = Unprotect-SxValue $m.Enc
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
            Value = Unprotect-SxValue $_.Enc
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
    $store.secrets[$p.scope].Remove($p.name)
    Save-SxStore $store
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

function Format-SxCell([string]$s, [int]$w) {
    if ($null -eq $s) { $s = '' }
    if ($s.Length -ge $w) { return $s.Substring(0, $w) }
    return $s + (' ' * ($w - $s.Length))
}

function Write-SxRow($leftText, $rightText, $colW, $leftHl, $rightHl, $activeLeft, $activeRight) {
    Write-Host '|' -NoNewline -ForegroundColor DarkGray
    if ($leftHl -and $activeLeft) {
        Write-Host (Format-SxCell $leftText $colW) -NoNewline -ForegroundColor Black -BackgroundColor Cyan
    } elseif ($leftHl) {
        Write-Host (Format-SxCell $leftText $colW) -NoNewline -ForegroundColor Cyan
    } else {
        Write-Host (Format-SxCell $leftText $colW) -NoNewline -ForegroundColor Gray
    }
    Write-Host '|' -NoNewline -ForegroundColor DarkGray
    if ($rightHl -and $activeRight) {
        Write-Host (Format-SxCell $rightText $colW) -NoNewline -ForegroundColor Black -BackgroundColor Cyan
    } elseif ($rightHl) {
        Write-Host (Format-SxCell $rightText $colW) -NoNewline -ForegroundColor Cyan
    } else {
        Write-Host (Format-SxCell $rightText $colW) -NoNewline -ForegroundColor Gray
    }
    Write-Host '|' -ForegroundColor DarkGray
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

        $state = [ordered]@{
            Screen      = 'root'
            Pane        = 0
            SelPersonal = 0
            SelProject  = 0
            SelInProj   = 0
            Project     = ''
            Flash       = ''
            FlashColor  = 'Green'
        }

        while ($true) {
            $store    = Get-SxStore
            $personal = @($store.secrets['~'].Keys | Sort-Object)
            $projects = @($store.projects.Keys    | Sort-Object)

            if ($state.SelPersonal -ge $personal.Count) { $state.SelPersonal = [Math]::Max(0, $personal.Count - 1) }
            if ($state.SelProject  -ge $projects.Count) { $state.SelProject  = [Math]::Max(0, $projects.Count - 1) }

            $w = 80
            try { $w = [Console]::WindowWidth } catch {}
            if ($w -lt 50) { $w = 50 }
            $colW = [Math]::Floor(($w - 3) / 2)

            Clear-Host

            Write-Host ''
            Write-Host '  secrex' -NoNewline -ForegroundColor Magenta
            Write-Host ('   ' + $personal.Count + ' personal / ' + $projects.Count + ' projects') -ForegroundColor DarkGray
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

                $rows = [Math]::Max($personal.Count, $projects.Count)
                if ($rows -eq 0) { $rows = 1 }
                for ($i = 0; $i -lt $rows; $i++) {
                    $lText = ''
                    if ($i -lt $personal.Count) {
                        $lText = '  ' + $personal[$i]
                    } elseif ($personal.Count -eq 0 -and $i -eq 0) {
                        $lText = '  (empty)'
                    }
                    $rText = ''
                    if ($i -lt $projects.Count) {
                        $rText = '  ' + $projects[$i]
                    } elseif ($projects.Count -eq 0 -and $i -eq 0) {
                        $rText = '  (empty)'
                    }
                    $lHl = ($i -eq $state.SelPersonal) -and ($personal.Count -gt 0)
                    $rHl = ($i -eq $state.SelProject)  -and ($projects.Count -gt 0)
                    Write-SxRow $lText $rText $colW $lHl $rHl ($state.Pane -eq 0) ($state.Pane -eq 1)
                }
                Write-Host ('+' + ('-' * $colW) + '+' + ('-' * $colW) + '+') -ForegroundColor DarkGray

                Write-Host ''
                Write-Host '  up/dn' -NoNewline -ForegroundColor Yellow
                Write-Host ' nav  ' -NoNewline -ForegroundColor DarkGray
                Write-Host 'Tab' -NoNewline -ForegroundColor Yellow
                Write-Host ' switch  ' -NoNewline -ForegroundColor DarkGray
                Write-Host 'Enter' -NoNewline -ForegroundColor Yellow
                Write-Host ' open/copy  ' -NoNewline -ForegroundColor DarkGray
                Write-Host 'q/Esc' -NoNewline -ForegroundColor Yellow
                Write-Host ' quit' -ForegroundColor DarkGray
            }
            else {
                $secrets = @()
                if ($store.secrets.ContainsKey($state.Project)) {
                    $secrets = @($store.secrets[$state.Project].Keys | Sort-Object)
                }
                if ($state.SelInProj -ge $secrets.Count) { $state.SelInProj = [Math]::Max(0, $secrets.Count - 1) }

                $fullW = ($colW * 2) + 1
                $hdr = " $($state.Project)"
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

                Write-Host ''
                Write-Host '  up/dn' -NoNewline -ForegroundColor Yellow
                Write-Host ' nav  ' -NoNewline -ForegroundColor DarkGray
                Write-Host 'Enter' -NoNewline -ForegroundColor Yellow
                Write-Host ' copy  ' -NoNewline -ForegroundColor DarkGray
                Write-Host 'Esc' -NoNewline -ForegroundColor Yellow
                Write-Host ' back  ' -NoNewline -ForegroundColor DarkGray
                Write-Host 'q' -NoNewline -ForegroundColor Yellow
                Write-Host ' quit' -ForegroundColor DarkGray
            }

            if ($state.Flash) {
                Write-Host ''
                Write-Host "  $($state.Flash)" -ForegroundColor $state.FlashColor
                $state.Flash = ''
            }

            if ($env:SECREX_TUI_DRYRUN -eq '1') { return }
            $key = [Console]::ReadKey($true)

            if ($state.Screen -eq 'root') {
                switch ($key.Key) {
                    'Escape'     { return }
                    'Q'          { return }
                    'Tab'        { $state.Pane = 1 - $state.Pane }
                    'LeftArrow'  { $state.Pane = 0 }
                    'RightArrow' { $state.Pane = 1 }
                    'UpArrow' {
                        if ($state.Pane -eq 0 -and $state.SelPersonal -gt 0) { $state.SelPersonal-- }
                        elseif ($state.Pane -eq 1 -and $state.SelProject -gt 0) { $state.SelProject-- }
                    }
                    'DownArrow' {
                        if ($state.Pane -eq 0 -and $state.SelPersonal -lt $personal.Count - 1) { $state.SelPersonal++ }
                        elseif ($state.Pane -eq 1 -and $state.SelProject -lt $projects.Count - 1) { $state.SelProject++ }
                    }
                    'Enter' {
                        if ($state.Pane -eq 0 -and $personal.Count -gt 0) {
                            $name = $personal[$state.SelPersonal]
                            $plain = Unprotect-SxValue $store.secrets['~'][$name]
                            Set-Clipboard -Value $plain
                            $state.Flash = "copied: ~/$name"
                            $state.FlashColor = 'Green'
                        }
                        elseif ($state.Pane -eq 1 -and $projects.Count -gt 0) {
                            $state.Project   = $projects[$state.SelProject]
                            $state.Screen    = 'project'
                            $state.SelInProj = 0
                        }
                    }
                }
            }
            else {
                switch ($key.Key) {
                    'Escape' { $state.Screen = 'root' }
                    'Q'      { return }
                    'Backspace' { $state.Screen = 'root' }
                    'LeftArrow' { $state.Screen = 'root' }
                    'UpArrow' { if ($state.SelInProj -gt 0) { $state.SelInProj-- } }
                    'DownArrow' {
                        $pSecrets = @($store.secrets[$state.Project].Keys)
                        if ($state.SelInProj -lt $pSecrets.Count - 1) { $state.SelInProj++ }
                    }
                    'Enter' {
                        $pSecrets = @($store.secrets[$state.Project].Keys | Sort-Object)
                        if ($pSecrets.Count -gt 0) {
                            $name = $pSecrets[$state.SelInProj]
                            $plain = Unprotect-SxValue $store.secrets[$state.Project][$name]
                            Set-Clipboard -Value $plain
                            $state.Flash = "copied: $($state.Project)/$name"
                            $state.FlashColor = 'Green'
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
secrex -- per-user secret manager (DPAPI-encrypted at $script:StorePath)

Commands:
  init   | i                register current folder as a project
  set    | s | add | a <path> [value]  store secret (prompts if no value)
  get    | g   <path>       print secret     [-AsSecureString] [-Copy]
  list   | ls  [filter]     list secrets
  remove | rm  <path>       delete secret

Paths:
  openai              personal (same as ~/openai)
  ~/openai            personal, explicit
  myapp/openai        project myapp

List filters:
  <empty>             everything
  ~                   all personal
  projects            registered projects
  myapp  | myapp/     all in project myapp
  /openai             all secrets named openai across scopes

Examples:
  # register current folder as a project (uses folder name)
  cd D:\Tools\myapp
  secrex init

  # add a personal secret, interactive hidden prompt
  secrex add openai
  secrex add ~/openai

  # add a secret inside project myapp, interactive
  secrex add myapp/openai
  secrex a myapp/github

  # add with value inline (WARNING: goes into PS history)
  secrex add bright-data 1d045222
  secrex add myapp/github ghp_xxx

  # read an exact secret
  secrex get ~/openai
  secrex g  myapp/openai
  secrex g  myapp/openai -Copy          # put value into clipboard
  `$sec = secrex g myapp/openai -AsSecureString

  # read by wildcard (returns Path+Value rows)
  secrex g 'bri*'                        # personal, names starting with 'bri'
  secrex g 'myapp/*'                     # everything in project myapp
  secrex g '/bright-data'                # 'bright-data' across all scopes
  secrex g '*/bri*'                      # all scopes, names starting with 'bri'

  # list things
  secrex ls                              # every secret, every scope
  secrex ls ~                            # only personal
  secrex ls projects                     # registered projects + their paths
  secrex ls myapp                        # everything in project myapp
  secrex ls /openai                      # 'openai' across all scopes

  # delete
  secrex rm myapp/github
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
    if ([string]::IsNullOrEmpty($Command)) { Invoke-SxTui; return }
    switch ($Command) {
        'help'      { Show-SxHelp; return }
        '-h'        { Show-SxHelp; return }
        '--help'    { Show-SxHelp; return }
    }
    $handler = switch ($Command) {
        { $_ -in 'init','i' }             { 'Invoke-SxInit';   break }
        { $_ -in 'set','s','add','a' }    { 'Invoke-SxSet';    break }
        { $_ -in 'get','g' }              { 'Invoke-SxGet';    break }
        { $_ -in 'list','ls' }            { 'Invoke-SxList';   break }
        { $_ -in 'remove','rm' }          { 'Invoke-SxRemove'; break }
        default { throw "Unknown command: '$Command'. Run 'secrex help'." }
    }
    $split = Split-SxArgs $Rest
    $pos   = @($split.Positional)
    $named = $split.Named
    & $handler @pos @named
}

Set-Alias -Name secrex -Value Invoke-Secrex
Export-ModuleMember -Function Invoke-Secrex -Alias secrex
