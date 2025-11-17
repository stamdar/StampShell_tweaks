# ================================
#  Custom StampShell Profile
# ================================

# Import core modules
Import-Module PSReadLine -ErrorAction SilentlyContinue
Import-Module Terminal-Icons -ErrorAction SilentlyContinue
Import-Module posh-git -ErrorAction SilentlyContinue
Import-Module PSFzf -ErrorAction SilentlyContinue

# Import Catppuccin (if available) and set Mocha flavor
try {
    Import-Module Catppuccin -ErrorAction Stop
    $Flavor = $Catppuccin['Mocha']
} catch { }

# Use real GNU grep instead of Select-String alias if available
if (Get-Command grep.exe -ErrorAction SilentlyContinue) {
    if (Get-Item Alias:grep -ErrorAction SilentlyContinue) {
        Remove-Item Alias:grep -ErrorAction SilentlyContinue
    }
}

# Aliases
Set-Alias -Name ifconfig -Value ipconfig -ErrorAction SilentlyContinue
Set-Alias -Name ll       -Value ls       -ErrorAction SilentlyContinue
Set-Alias -Name reboot   -Value Restart-Computer -ErrorAction SilentlyContinue
Set-Alias -Name c        -Value Clear-And-Banner -ErrorAction SilentlyContinue
Set-Alias -Name shell    -Value PowerShell -ErrorAction SilentlyContinue

function cd.. {
    Set-Location "..\.."
}

function explore {
    param(
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $target = (Get-Location).Path
    } else {
        try {
            $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
            $target = $resolved.Path
        } catch {
            Write-Warning "Path not found: $Path"
            return
        }
    }
    Start-Process explorer.exe -ArgumentList $target
}

function pkill {
    param(
        [Parameter(Mandatory)][string]$procName
    )
    try {
        taskkill /f /im $procName 2>$null
    } catch {
        Write-Warning "Failed to kill process ${procName}: $($_.Exception.Message)"
    }
}

function Clear-And-Banner {
    $banner = @"
  _____ __                           ____ __         ____
 / ___// /_ ____ ________  ____     / __// /_  ___  / / /
 \__ \/ __/ __  / __  __ \/ __ \    \__ \/ __ \/ _ \/ / /
 __/ / /_/ /_/ / / / / / / /_/ /   __/ / / / /  __/ / /
/___/\__/\__,_/_/ /_/ /_/ .___/   /___/_/ /_/\___/_/_/
                       /_/
"@

    function Get-PrimaryIPv4 {
        try {
            $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
                            Sort-Object -Property RouteMetric, InterfaceMetric |
                            Select-Object -First 1
            if ($defaultRoute) {
                $ifIndex = $defaultRoute.InterfaceIndex
                $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $ifIndex -ErrorAction Stop |
                     Where-Object { $_.IPAddress -notlike "169.254.*" } |
                     Select-Object -First 1 -ExpandProperty IPAddress
                return $ip
            }
        } catch { }
        try {
            $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                  Where-Object { $_.IPAddress -notlike "169.254.*" } |
                  Select-Object -First 1 -ExpandProperty IPAddress
            return $ip
        } catch { }
        return $null
    }

    $ip = Get-PrimaryIPv4
    $ipText = if ($ip) { $ip } else { "(none)" }
    $ipStr = "IPv4 addr: " + $ipText

    $pubStr = "Public IP: (unavailable)"
    try {
        $resp = Invoke-WebRequest "https://ifconfig.me/ip" -UseBasicParsing -TimeoutSec 3
        if ($resp -and $resp.Content) {
            $pubStr = "Public IP: " + $resp.Content.Trim()
        }
    } catch { }

    $hn = $env:COMPUTERNAME
    $hnStr = "HN: $hn"

    Clear-Host
    Write-Output $banner
    Get-Date
    Write-Output $hnStr
    Write-Output $ipStr
    Write-Host $pubStr -NoNewline
}

function Add-Path {
    param(
        [Parameter(Mandatory)][string]$NewPath,
        [ValidateSet('User','Machine')][string]$Scope = 'Machine'
    )
    if (-not (Test-Path $NewPath)) {
        Write-Warning "Path does not exist: $NewPath"
        return
    }

    $targetScope = $Scope
    try {
        $current = [Environment]::GetEnvironmentVariable('Path', $targetScope)
    } catch {
        Write-Warning "Failed to read $targetScope PATH, falling back to User."
        $targetScope = 'User'
        $current = [Environment]::GetEnvironmentVariable('Path', $targetScope)
    }

    if ($current -and $current -match [Regex]::Escape($NewPath)) {
        Write-Host "[=] $NewPath already in $targetScope PATH."
    } else {
        $sep = if ([string]::IsNullOrEmpty($current) -or $current.TrimEnd().EndsWith(';')) { '' } else { ';' }
        [Environment]::SetEnvironmentVariable('Path', "$current$sep$NewPath", $targetScope)
        Write-Host "[+] Added $NewPath to $targetScope PATH."
    }

    # Refresh current session PATH
    $machinePath = [Environment]::GetEnvironmentVariable('Path','Machine')
    $userPath    = [Environment]::GetEnvironmentVariable('Path','User')
    $env:Path    = "$machinePath;$userPath"
}

function sign {
    param(
        [Parameter(Mandatory)][string]$FilePath
    )
    $resolved = Resolve-Path -LiteralPath $FilePath -ErrorAction SilentlyContinue
    if (-not $resolved) {
        Write-Error "File not found: $FilePath"
        return
    }

    $CertSubject = "CN=Script Signing - $env:USERNAME"
    $Certificate = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert |
                   Where-Object { $_.Subject -eq $CertSubject } |
                   Select-Object -First 1

    if (-not $Certificate) {
        Write-Error "Script signing certificate not found for subject: $CertSubject"
        return
    }

    try {
        Set-AuthenticodeSignature -FilePath $resolved.Path -Certificate $Certificate | Out-Null
        Write-Host "[+] Signed $($resolved.Path) with certificate subject $CertSubject" -ForegroundColor Green
    } catch {
        Write-Error "Failed to sign file: $($_.Exception.Message)"
    }
}

function Show-ProfileHelp {
    Write-Host "=== Custom Profile Features ===" -ForegroundColor Cyan

    Write-Host "`nAliases:" -ForegroundColor Yellow
    Write-Host "  ifconfig -> ipconfig"
    Write-Host "  ll       -> ls"
    Write-Host "  reboot   -> Restart-Computer"
    Write-Host "  c        -> Clear-And-Banner"
    Write-Host "  shell    -> PowerShell"
    Write-Host "  cd..     -> go up two directories"
    Write-Host "  grep     -> GNU grep (binary), not Select-String"

    Write-Host "`nFunctions:" -ForegroundColor Yellow
    Write-Host "  explore [path]       : Open current or specified directory in Explorer"
    Write-Host "  pkill <name>         : taskkill /f /im <name> (with safer handling)"
    Write-Host "  Clear-And-Banner     : Clear screen + banner + host/IP info"
    Write-Host "  Add-Path <path>      : Add to PATH (Machine by default), auto-refresh session"
    Write-Host "  sign <file>          : Sign a single script with your signing certificate"
    Write-Host "  Show-ProfileHelp     : Show this help"

    Write-Host "`nTheming & shell goodies:" -ForegroundColor Yellow
    Write-Host "  - Catppuccin Mocha prompt & PSReadLine colors (if Catppuccin module available)"
    Write-Host "  - Terminal-Icons for ls output"
    Write-Host "  - posh-git for git status/prompt integration"
    Write-Host "  - PSFzf + fzf for fuzzy history/path search"

    Write-Host "`nTip: Customize this profile at `"$PROFILE`"."
}

Set-Alias -Name profile-help -Value Show-ProfileHelp -ErrorAction SilentlyContinue

function Prompt {
    # Figure out time of last completed command (or now if none)
    $timeText = ""
    $hist = Get-History -ErrorAction SilentlyContinue | Select-Object -Last 1
    if ($hist -and $hist.EndExecutionTime) {
        $timeText = $hist.EndExecutionTime.ToString("HH:mm:ss")
    } else {
        $timeText = (Get-Date).ToString("HH:mm:ss")
    }

    $path = (Get-Location).Path

    # Decide if we should use ANSI colors (only in pwsh 7+ with PSStyle)
    $useColor = $false
    if ($PSVersionTable.PSVersion.Major -ge 7 -and $PSStyle) {
        $useColor = $true
    }

    $reset = ""
    $timeColor = ""
    $pathColor = ""
    $promptColor = ""

    if ($useColor -and $Flavor) {
        $reset       = $PSStyle.Reset
        $timeColor   = $Flavor.Teal.Foreground()
        $pathColor   = $Flavor.Yellow.Foreground()
        $promptColor = $Flavor.Green.Foreground()
    }

    Write-Host "[" -NoNewline

    if ($useColor -and $timeColor) {
        Write-Host "$timeColor$timeText$reset" -NoNewline
    } else {
        Write-Host "$timeText" -NoNewline
    }

    Write-Host "] " -NoNewline

    if ($useColor -and $pathColor) {
        Write-Host "$pathColor$path$reset" -NoNewline
    } else {
        Write-Host "$path" -NoNewline
    }

    if ($useColor -and $promptColor) {
        Write-Host " $promptColor> $reset" -NoNewline
    } else {
        Write-Host " > " -NoNewline
    }

    return " "
}

# --- Print banner at startup ---
Clear-And-Banner -ErrorAction SilentlyContinue