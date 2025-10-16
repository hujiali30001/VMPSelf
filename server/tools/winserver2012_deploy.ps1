param(
    [string]$InstallRoot = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)),
    [string]$PythonExe = "C:\\Python313\\python.exe",
    [string]$ServiceName = "VMPAuthService",
    [int]$Port = 8000,
    [string]$Host = "0.0.0.0",
    [string]$NssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
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
