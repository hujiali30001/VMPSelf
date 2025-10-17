param(
    [string]$InstallRoot = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)),
    [string]$PythonExe = "C:\\Python313\\python.exe",
    [string]$ServiceName = "VMPAuthService",
    [int]$Port = 8000,
    [string]$Host = "0.0.0.0",
    [string]$NssmUrl = "https://nssm.cc/release/nssm-2.24.zip",
    [string]$AdminUser,
    [string]$AdminPassword,
    [string]$HmacSecret,
    [string]$SqlitePath
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param(
        [string]$Message
    )
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Assert-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "请以管理员权限运行此脚本。"
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

Assert-Admin

$InstallRoot = Resolve-AbsolutePath -Path $InstallRoot
if (-not $InstallRoot) {
    throw "InstallRoot 无法解析。"
}

if (-not (Test-Path -LiteralPath $InstallRoot)) {
    Write-Step "创建安装目录 $InstallRoot"
    New-Item -ItemType Directory -Path $InstallRoot | Out-Null
}

Set-Location -Path $InstallRoot

if (-not (Test-Path -LiteralPath $PythonExe)) {
    throw "未找到 Python 可执行文件：$PythonExe"
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoServerPath = Split-Path -Parent $ScriptDir
$LogsPath = Join-Path $InstallRoot "logs"
if (-not (Test-Path -LiteralPath $LogsPath)) {
    New-Item -ItemType Directory -Path $LogsPath | Out-Null
}

$VenvPath = Join-Path $InstallRoot ".venv"
$VenvPython = Join-Path $VenvPath "Scripts\python.exe"

if (-not (Test-Path -LiteralPath $VenvPython)) {
    Write-Step "创建虚拟环境 (.venv)"
    & $PythonExe -m venv $VenvPath
}

Write-Step "升级 pip"
& $VenvPython -m pip install --upgrade pip

Write-Step "安装 Python 依赖"
& $VenvPython -m pip install -r (Join-Path $RepoServerPath "requirements.txt")

$EnvFile = Join-Path $InstallRoot ".env"
if (-not (Test-Path -LiteralPath $EnvFile)) {
    $ExampleEnv = Join-Path $RepoServerPath ".env.example"
    if (Test-Path -LiteralPath $ExampleEnv) {
        Write-Step "首次部署，复制 .env.example"
        Copy-Item -Path $ExampleEnv -Destination $EnvFile -Force
    } else {
        Write-Step "未找到 .env.example，请手动创建 .env"
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

$existingHmac = $null
if ($ExistingEnv.ContainsKey("VMP_HMAC_SECRET")) {
    $existingHmac = $ExistingEnv["VMP_HMAC_SECRET"]
}
$FinalHmacSecret = if ($HmacSecret) { $HmacSecret } elseif ([string]::IsNullOrWhiteSpace($existingHmac) -or $existingHmac -in @("super-secret-key", "change-me")) { New-RandomToken -Bytes 48 } else { $existingHmac }
$FinalEnv["VMP_HMAC_SECRET"] = $FinalHmacSecret
$GeneratedHmacSecret = -not $HmacSecret -and ($FinalHmacSecret -ne $existingHmac)

$existingAdminUser = $null
if ($ExistingEnv.ContainsKey("VMP_ADMIN_USER")) {
    $existingAdminUser = $ExistingEnv["VMP_ADMIN_USER"]
}
$FinalAdminUser = if ($AdminUser) { $AdminUser } elseif (-not [string]::IsNullOrWhiteSpace($existingAdminUser)) { $existingAdminUser } else { "admin" }
$FinalEnv["VMP_ADMIN_USER"] = $FinalAdminUser

$existingAdminPass = $null
if ($ExistingEnv.ContainsKey("VMP_ADMIN_PASS")) {
    $existingAdminPass = $ExistingEnv["VMP_ADMIN_PASS"]
}
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

Write-Step "已更新 .env 关键信息"
Write-Host "    VMP_ENV = $($FinalEnv["VMP_ENV"])"
Write-Host "    VMP_SQLITE_PATH = $($FinalEnv["VMP_SQLITE_PATH"])"
if ($GeneratedHmacSecret) {
    Write-Host "    VMP_HMAC_SECRET 已生成新值" -ForegroundColor Yellow
} elseif ($HmacSecret) {
    Write-Host "    VMP_HMAC_SECRET 已按参数更新" -ForegroundColor Yellow
} else {
    Write-Host "    VMP_HMAC_SECRET 保留现有配置"
}
if ($AdminUser) {
    Write-Host "    VMP_ADMIN_USER 已按参数更新" -ForegroundColor Yellow
} else {
    Write-Host "    VMP_ADMIN_USER = $FinalAdminUser"
}
if ($GeneratedAdminPassword) {
    Write-Host "    VMP_ADMIN_PASS 已生成新值" -ForegroundColor Yellow
} elseif ($AdminPassword) {
    Write-Host "    VMP_ADMIN_PASS 已按参数更新" -ForegroundColor Yellow
} else {
    Write-Host "    VMP_ADMIN_PASS 保留现有配置"
}

Write-Step "初始化 SQLite 数据库"
& $VenvPython (Join-Path $RepoServerPath "manage.py") init-db

Write-Step "准备 NSSM"
$NssmDir = Join-Path $InstallRoot "tools\nssm"
$NssmExe = Join-Path $NssmDir "nssm.exe"
if (-not (Test-Path -LiteralPath $NssmExe)) {
    if (-not (Test-Path -LiteralPath $NssmDir)) {
        New-Item -ItemType Directory -Path $NssmDir | Out-Null
    }
    $TempZip = Join-Path $env:TEMP "nssm.zip"
    Invoke-WebRequest -Uri $NssmUrl -OutFile $TempZip
    $TempDir = Join-Path $env:TEMP "nssm-extract"
    if (Test-Path -LiteralPath $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force
    }
    Expand-Archive -Path $TempZip -DestinationPath $TempDir -Force
    $Candidate = Get-ChildItem -Path $TempDir -Recurse -Filter "nssm.exe" | Where-Object { $_.FullName -match "win64" } | Select-Object -First 1
    if (-not $Candidate) {
        throw "未在 NSSM 压缩包中找到 win64 版本。"
    }
    Copy-Item -Path $Candidate.FullName -Destination $NssmExe -Force
    Remove-Item -Path $TempZip -Force
    Remove-Item -Path $TempDir -Recurse -Force
}

function Invoke-Nssm {
    param([string[]]$Arguments)
    $process = Start-Process -FilePath $NssmExe -ArgumentList $Arguments -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "NSSM 命令失败: $($Arguments -join ' ')";
    }
}

Write-Step "注册 Windows 服务 $ServiceName"
$ServiceExists = $false
try {
    $process = Start-Process -FilePath $NssmExe -ArgumentList @("status", $ServiceName) -NoNewWindow -Wait -PassThru -ErrorAction Stop
    $ServiceExists = $process.ExitCode -lt 4
} catch {
    $ServiceExists = $false
}

if ($ServiceExists) {
    Write-Step "服务已存在，执行停止与移除"
    try { Start-Process -FilePath $NssmExe -ArgumentList @("stop", $ServiceName) -NoNewWindow -Wait } catch {}
    Start-Process -FilePath $NssmExe -ArgumentList @("remove", $ServiceName, "confirm") -NoNewWindow -Wait | Out-Null
}

$AppArgs = "-m", "uvicorn", "app.main:app", "--host", $Host, "--port", $Port.ToString(), "--env-file", $EnvFile, "--log-level", "info"
Invoke-Nssm -Arguments @("install", $ServiceName, $VenvPython) + $AppArgs
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

Write-Step "配置防火墙规则"
$FirewallName = "VMP Auth API"
$existingRule = Get-NetFirewallRule -DisplayName $FirewallName -ErrorAction SilentlyContinue
if (-not $existingRule) {
    New-NetFirewallRule -DisplayName $FirewallName -Direction Inbound -Profile Any -Action Allow -Protocol TCP -LocalPort $Port | Out-Null
} else {
    Write-Step "防火墙规则已存在"
}

Write-Step "启动服务"
Invoke-Nssm -Arguments @("start", $ServiceName)

Write-Step "部署完成。当前监听地址: http://$Host:$Port"

Write-Host "" 
Write-Host "后台登录地址: http://$Host:$Port/admin/licenses" -ForegroundColor Green
Write-Host "用户管理入口: http://$Host:$Port/admin/users" -ForegroundColor Green
Write-Host "HTTP Basic 用户名: $FinalAdminUser"
if ($GeneratedAdminPassword) {
    Write-Host "HTTP Basic 密码: $FinalAdminPass (已自动生成，请立即备份)" -ForegroundColor Yellow
} elseif ($AdminPassword) {
    Write-Host "HTTP Basic 密码已更新为参数指定值" -ForegroundColor Yellow
} else {
    Write-Host "HTTP Basic 密码保持当前配置"
}

if ($GeneratedHmacSecret) {
    Write-Host "HMAC 密钥已自动生成：$FinalHmacSecret" -ForegroundColor Yellow
} elseif ($HmacSecret) {
    Write-Host "HMAC 密钥已按参数更新" -ForegroundColor Yellow
} else {
    Write-Host "HMAC 密钥保持当前配置"
}

Write-Host "如需变更服务配置，可编辑 $EnvFile 并执行： nssm restart $ServiceName"
