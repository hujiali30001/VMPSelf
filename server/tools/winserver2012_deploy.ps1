param(
    [string]$InstallRoot = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)),
    [string]$PythonExe = "C:\\Python313\\python.exe",
    [string]$ServiceName = "VMPAuthService",
    [int]$Port = 8000,
    [Alias("Host")]
    [string]$ListenHost = "0.0.0.0",
    [string]$NssmUrl = "https://nssm.cc/release/nssm-2.24.zip",
    [string]$AdminUser,
    [string]$AdminPassword,
    [string]$HmacSecret,
    [string]$SqlitePath
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ("[+] {0}" -f $Message) -ForegroundColor Cyan
}

function Assert-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function Resolve-AbsolutePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }
    if (Test-Path -LiteralPath $Path) {
        return (Resolve-Path -LiteralPath $Path).Path
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function New-RandomToken {
    param([int]$Bytes = 32)
    $count = if ($Bytes -lt 8) { 8 } else { $Bytes }
    $buffer = New-Object byte[] $count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($buffer)
    } finally {
        $rng.Dispose()
    }
    return ([Convert]::ToBase64String($buffer)).TrimEnd('=')
}

function Get-EnvMap {
    param([string]$FilePath)
    $map = @{}
    if (-not (Test-Path -LiteralPath $FilePath)) {
        return $map
    }

    foreach ($line in Get-Content -Path $FilePath -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith("#")) {
            continue
        }
        $parts = $trimmed -split "=", 2
        if ($parts.Length -eq 2) {
            $map[$parts[0].Trim()] = $parts[1].Trim()
        }
    }

    return $map
}

function Update-EnvFile {
    param(
        [string]$FilePath,
        [hashtable]$Updates
    )

    $lines = @()
    if (Test-Path -LiteralPath $FilePath) {
        $lines = Get-Content -Path $FilePath -Encoding UTF8
    }

    $handled = @{}
    for ($i = 0; $i -lt $lines.Count; $i++) {
        foreach ($key in $Updates.Keys) {
            $pattern = "^\s*{0}\s*=" -f [regex]::Escape($key)
            if ($lines[$i] -match $pattern) {
                $lines[$i] = "$key=$($Updates[$key])"
                $handled[$key] = $true
            }
        }
    }

    foreach ($key in $Updates.Keys) {
        if (-not $handled.ContainsKey($key)) {
            $lines += "$key=$($Updates[$key])"
        }
    }

    Set-Content -Path $FilePath -Value $lines -Encoding UTF8
}

function Ensure-Tls12 {
    if (-not ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
}

Assert-Admin

$InstallRoot = Resolve-AbsolutePath -Path $InstallRoot
if (-not $InstallRoot) {
    throw "InstallRoot could not be resolved."
}

if (-not (Test-Path -LiteralPath $InstallRoot)) {
    Write-Step ("Creating install directory: {0}" -f $InstallRoot)
    New-Item -ItemType Directory -Path $InstallRoot | Out-Null
}

Set-Location -Path $InstallRoot

if (-not (Test-Path -LiteralPath $PythonExe)) {
    throw ("Python executable not found: {0}" -f $PythonExe)
}

$ToolsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerDir = Split-Path -Parent $ToolsDir
$RepoDir = Split-Path -Parent $ServerDir
$LogsPath = Join-Path $InstallRoot "logs"
if (-not (Test-Path -LiteralPath $LogsPath)) {
    New-Item -ItemType Directory -Path $LogsPath | Out-Null
}

$VenvPath = Join-Path $InstallRoot ".venv"
$VenvPython = Join-Path $VenvPath "Scripts\python.exe"

if (-not (Test-Path -LiteralPath $VenvPython)) {
    Write-Step "Creating virtual environment (.venv)"
    & $PythonExe -m venv $VenvPath
}

Write-Step "Upgrading pip"
& $VenvPython -m pip install --upgrade pip

Write-Step "Installing Python dependencies"
$RequirementsPath = Join-Path $ServerDir "requirements.txt"
if (-not (Test-Path -LiteralPath $RequirementsPath)) {
    throw "requirements.txt was not found beside the server folder."
}
& $VenvPython -m pip install -r $RequirementsPath

$EnvFile = Join-Path $InstallRoot ".env"
if (-not (Test-Path -LiteralPath $EnvFile)) {
    $ExampleEnv = Join-Path $ServerDir ".env.example"
    if (Test-Path -LiteralPath $ExampleEnv) {
        Write-Step "Copying .env.example"
        Copy-Item -Path $ExampleEnv -Destination $EnvFile -Force
    } else {
        Write-Step "Creating empty .env"
        New-Item -Path $EnvFile -ItemType File | Out-Null
    }
}

$ExistingEnv = Get-EnvMap -FilePath $EnvFile

$FinalEnv = @{}
$FinalEnv["VMP_ENV"] = "production"

$resolvedSqlitePath = $null
if ($SqlitePath) {
    $resolvedSqlitePath = Resolve-AbsolutePath -Path $SqlitePath
} elseif ($ExistingEnv.ContainsKey("VMP_SQLITE_PATH") -and $ExistingEnv["VMP_SQLITE_PATH"]) {
    $resolvedSqlitePath = Resolve-AbsolutePath -Path $ExistingEnv["VMP_SQLITE_PATH"]
    if ($ExistingEnv["VMP_SQLITE_PATH"] -eq "data/license.db") {
        $resolvedSqlitePath = Join-Path $InstallRoot "data\license.db"
    }
} else {
    $resolvedSqlitePath = Join-Path $InstallRoot "data\license.db"
}

if ($resolvedSqlitePath) {
    $sqliteDir = Split-Path -Parent $resolvedSqlitePath
    if ($sqliteDir -and -not (Test-Path -LiteralPath $sqliteDir)) {
        New-Item -ItemType Directory -Path $sqliteDir -Force | Out-Null
    }
    $FinalEnv["VMP_SQLITE_PATH"] = ($resolvedSqlitePath -replace "\\", "/")
}

$existingHmac = if ($ExistingEnv.ContainsKey("VMP_HMAC_SECRET")) { $ExistingEnv["VMP_HMAC_SECRET"] } else { $null }
$FinalHmacSecret = if ($HmacSecret) { $HmacSecret } elseif ([string]::IsNullOrWhiteSpace($existingHmac) -or $existingHmac -in @("super-secret-key", "change-me")) { New-RandomToken -Bytes 48 } else { $existingHmac }
$FinalEnv["VMP_HMAC_SECRET"] = $FinalHmacSecret
$GeneratedHmacSecret = -not $HmacSecret -and ($FinalHmacSecret -ne $existingHmac)

$existingAdminUser = if ($ExistingEnv.ContainsKey("VMP_ADMIN_USER")) { $ExistingEnv["VMP_ADMIN_USER"] } else { $null }
$FinalAdminUser = if ($AdminUser) { $AdminUser } elseif (-not [string]::IsNullOrWhiteSpace($existingAdminUser)) { $existingAdminUser } else { "admin" }
$FinalEnv["VMP_ADMIN_USER"] = $FinalAdminUser

$existingAdminPass = if ($ExistingEnv.ContainsKey("VMP_ADMIN_PASS")) { $ExistingEnv["VMP_ADMIN_PASS"] } else { $null }
$GeneratedAdminPassword = $false
if ($AdminPassword) {
    $FinalAdminPass = $AdminPassword
} elseif ([string]::IsNullOrWhiteSpace($existingAdminPass) -or $existingAdminPass -in @("super-admin-password", "change-me", "password")) {
    $FinalAdminPass = New-RandomToken -Bytes 36
    $GeneratedAdminPassword = $true
} else {
    $FinalAdminPass = $existingAdminPass
}
$FinalEnv["VMP_ADMIN_PASS"] = $FinalAdminPass

Update-EnvFile -FilePath $EnvFile -Updates $FinalEnv

Write-Step "Updated .env"
Write-Host ("    VMP_ENV = {0}" -f $FinalEnv["VMP_ENV"])
Write-Host ("    VMP_SQLITE_PATH = {0}" -f $FinalEnv["VMP_SQLITE_PATH"])
if ($GeneratedHmacSecret) {
    Write-Host "    VMP_HMAC_SECRET refreshed" -ForegroundColor Yellow
} elseif ($HmacSecret) {
    Write-Host "    VMP_HMAC_SECRET set from parameter" -ForegroundColor Yellow
} else {
    Write-Host "    VMP_HMAC_SECRET unchanged"
}
if ($AdminUser) {
    Write-Host "    VMP_ADMIN_USER set from parameter" -ForegroundColor Yellow
} else {
    Write-Host ("    VMP_ADMIN_USER = {0}" -f $FinalAdminUser)
}
if ($GeneratedAdminPassword) {
    Write-Host "    VMP_ADMIN_PASS regenerated" -ForegroundColor Yellow
} elseif ($AdminPassword) {
    Write-Host "    VMP_ADMIN_PASS set from parameter" -ForegroundColor Yellow
} else {
    Write-Host "    VMP_ADMIN_PASS unchanged"
}

Write-Step "Initializing SQLite database"
$ManagePy = Join-Path $ServerDir "manage.py"
if (-not (Test-Path -LiteralPath $ManagePy)) {
    throw "manage.py was not found in the server directory."
}
& $VenvPython $ManagePy init-db

Write-Step "Preparing NSSM"
$NssmDir = Join-Path $InstallRoot "tools\nssm"
$NssmExe = Join-Path $NssmDir "nssm.exe"
if (-not (Test-Path -LiteralPath $NssmExe)) {
    if (-not (Test-Path -LiteralPath $NssmDir)) {
        New-Item -ItemType Directory -Path $NssmDir | Out-Null
    }
    Ensure-Tls12
    $TempZip = Join-Path $env:TEMP "nssm.zip"
    Invoke-WebRequest -Uri $NssmUrl -OutFile $TempZip
    $TempDir = Join-Path $env:TEMP "nssm-extract"
    if (Test-Path -LiteralPath $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force
    }
    Expand-Archive -Path $TempZip -DestinationPath $TempDir -Force
    $Candidate = Get-ChildItem -Path $TempDir -Recurse -Filter "nssm.exe" | Where-Object { $_.FullName -match "win64" } | Select-Object -First 1
    if (-not $Candidate) {
        throw "win64 nssm.exe was not found inside the archive."
    }
    Copy-Item -Path $Candidate.FullName -Destination $NssmExe -Force
    Remove-Item -Path $TempZip -Force
    Remove-Item -Path $TempDir -Recurse -Force
}

function Invoke-Nssm {
    param([string[]]$Arguments)
    $process = Start-Process -FilePath $NssmExe -ArgumentList $Arguments -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        $joinedArgs = $Arguments -join ' '
        throw ("NSSM command failed: {0}" -f $joinedArgs)
    }
}

Write-Step ("Configuring Windows service: {0}" -f $ServiceName)
$ServiceExists = $false
try {
    $statusProc = Start-Process -FilePath $NssmExe -ArgumentList @("status", $ServiceName) -NoNewWindow -Wait -PassThru -ErrorAction Stop
    $ServiceExists = $statusProc.ExitCode -lt 4
} catch {
    $ServiceExists = $false
}

if ($ServiceExists) {
    Write-Step "Existing service found; stopping and removing"
    try { Start-Process -FilePath $NssmExe -ArgumentList @("stop", $ServiceName) -NoNewWindow -Wait -ErrorAction SilentlyContinue | Out-Null } catch {}
    Start-Process -FilePath $NssmExe -ArgumentList @("remove", $ServiceName, "confirm") -NoNewWindow -Wait | Out-Null
}

$AppArgs = @(
    "-m", "uvicorn", "app.main:app",
    "--host", $ListenHost,
    "--port", $Port.ToString(),
    "--env-file", $EnvFile,
    "--log-level", "info"
)
Invoke-Nssm -Arguments (@("install", $ServiceName, $VenvPython) + $AppArgs)
Invoke-Nssm -Arguments @("set", $ServiceName, "AppDirectory", $InstallRoot)
Invoke-Nssm -Arguments @("set", $ServiceName, "DisplayName", "VMP Auth Service")
Invoke-Nssm -Arguments @("set", $ServiceName, "Description", "FastAPI-based license server for VMPSelf")
Invoke-Nssm -Arguments @("set", $ServiceName, "Start", "SERVICE_AUTO_START")
Invoke-Nssm -Arguments @("set", $ServiceName, "AppStdout", (Join-Path $LogsPath "uvicorn.log"))
Invoke-Nssm -Arguments @("set", $ServiceName, "AppStderr", (Join-Path $LogsPath "uvicorn.err.log"))
Invoke-Nssm -Arguments @("set", $ServiceName, "AppRotateFiles", "1")
Invoke-Nssm -Arguments @("set", $ServiceName, "AppRotateBytes", "10485760")
Invoke-Nssm -Arguments @("set", $ServiceName, "AppThrottle", "15000")
Invoke-Nssm -Arguments @("set", $ServiceName, "AppEnvironmentExtra", "VMP_ENV=production")

Write-Step "Configuring firewall rules"
$FirewallName = "VMP Auth API"
$existingRule = Get-NetFirewallRule -DisplayName $FirewallName -ErrorAction SilentlyContinue
if (-not $existingRule) {
    New-NetFirewallRule -DisplayName $FirewallName -Direction Inbound -Profile Any -Action Allow -Protocol TCP -LocalPort $Port | Out-Null
} else {
    Write-Step "Firewall rule already present"
}

Write-Step "Starting service"
Invoke-Nssm -Arguments @("start", $ServiceName)

$BaseUrl = "http://{0}:{1}" -f $ListenHost, $Port
Write-Step ("Deployment finished. Listening on {0}" -f $BaseUrl)

Write-Host ""
Write-Host (" Admin portal: {0}/admin/licenses" -f $BaseUrl) -ForegroundColor Green
Write-Host (" Users portal: {0}/admin/users" -f $BaseUrl) -ForegroundColor Green
Write-Host (" HTTP Basic user: {0}" -f $FinalAdminUser)
if ($GeneratedAdminPassword) {
    Write-Host (" HTTP Basic password: {0} (generated; store it safely)" -f $FinalAdminPass) -ForegroundColor Yellow
} elseif ($AdminPassword) {
    Write-Host " HTTP Basic password set from parameter" -ForegroundColor Yellow
} else {
    Write-Host " HTTP Basic password unchanged"
}

if ($GeneratedHmacSecret) {
    Write-Host (" HMAC secret regenerated: {0}" -f $FinalHmacSecret) -ForegroundColor Yellow
} elseif ($HmacSecret) {
    Write-Host " HMAC secret set from parameter" -ForegroundColor Yellow
} else {
    Write-Host " HMAC secret unchanged"
}

Write-Host (" To restart after editing {0}, run: nssm restart {1}" -f $EnvFile, $ServiceName)
