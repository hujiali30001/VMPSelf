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
    [string]$SqlitePath,
    [string]$MonitorEnabled,
    [ValidateRange(30, 3600)]
    [int]$MonitorIntervalSeconds = 300,
    [int]$CdnHealthCheckPort,
    [string]$SlotSecret,
    [string]$SlotCode = "default-slot",
    [ValidateSet("Prompt", "Fresh", "Upgrade", "Uninstall")]
    [string]$DeploymentMode = "Prompt"
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

function ConvertTo-NullableBoolean {
    param(
        [Parameter(ValueFromPipeline = $true)][object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    $text = $Value.ToString().Trim()
    if (-not $text) {
        return $null
    }

    switch ($text.ToLowerInvariant()) {
        "true" { return $true }
        "false" { return $false }
        "1" { return $true }
        "0" { return $false }
        "yes" { return $true }
        "no" { return $false }
        "on" { return $true }
        "off" { return $false }
        default {
            throw "Invalid boolean value: $text. Use true/false/1/0/yes/no/on/off."
        }
    }
}

function Get-AccessListInfo {
    param([string]$Value)

    $entries = @()
    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        foreach ($match in [System.Text.RegularExpressions.Regex]::Matches($Value, "[^,\s]+")) {
            $token = $match.Value.Trim()
            if ($token) {
                $entries += $token
            }
        }
    }

    $text = if ($entries.Count -gt 0) { ($entries -join ",") } else { "" }
    return [PSCustomObject]@{
        Entries = $entries
        Value   = $text
        Count   = $entries.Count
    }
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

function Expand-ZipArchiveCompat {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    $expandArchive = Get-Command -Name Expand-Archive -ErrorAction SilentlyContinue
    if ($expandArchive) {
        Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force
        return
    }

    if (-not (Get-Command -Name "Add-Type" -ErrorAction SilentlyContinue)) {
        throw "Current PowerShell environment cannot load compression assemblies for ZIP extraction."
    }

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    } catch {
        throw "Failed to load System.IO.Compression.FileSystem assembly: $($_.Exception.Message)"
    }

    if (-not (Test-Path -LiteralPath $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    try {
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $DestinationPath)
    } catch {
        throw "Failed to extract archive using .NET zip APIs: $($_.Exception.Message)"
    }
}

function Enter-DeletionSafeLocation {
    param([string]$TargetPath)

    $candidate = $null
    if (-not [string]::IsNullOrWhiteSpace($TargetPath)) {
        $candidate = Split-Path -Parent $TargetPath
    }

    if ([string]::IsNullOrWhiteSpace($candidate) -or -not (Test-Path -LiteralPath $candidate)) {
        if ($PSScriptRoot -and (Test-Path -LiteralPath $PSScriptRoot)) {
            $candidate = $PSScriptRoot
        } else {
            $candidate = [System.IO.Path]::GetPathRoot($TargetPath)
        }
    }

    if ([string]::IsNullOrWhiteSpace($candidate) -or -not (Test-Path -LiteralPath $candidate)) {
        $candidate = $env:SystemDrive + "\"
    }

    Set-Location -Path $candidate
}

function Select-DeploymentMode {
    param([string]$Mode)

    $normalized = if ([string]::IsNullOrWhiteSpace($Mode) -or $Mode -ieq "Prompt") {
        "prompt"
    } else {
        $Mode.ToLowerInvariant()
    }

    switch ($normalized) {
        "fresh" { return "Fresh" }
        "upgrade" { return "Upgrade" }
        "uninstall" { return "Uninstall" }
        default {
            Write-Host "" -ForegroundColor Gray
            Write-Host "选择部署方式:" -ForegroundColor Cyan
            Write-Host "  1) 全新部署 - 删除现有服务与数据后重新安装" -ForegroundColor Gray
            Write-Host "  2) 升级部署 - 保留数据/.env，只重建依赖与服务" -ForegroundColor Gray
            Write-Host "  3) 卸载 - 停止服务并移除所有文件后退出" -ForegroundColor Gray
            while ($true) {
                $choice = Read-Host "请输入选项编号 (1-3)"
                switch ($choice) {
                    "1" { return "Fresh" }
                    "2" { return "Upgrade" }
                    "3" { return "Uninstall" }
                    default { Write-Host "无效选项，请重新输入。" -ForegroundColor Yellow }
                }
            }
        }
    }
}

function Cleanup-PreviousDeployment {
    param(
        [string]$RootPath,
        [string]$ServiceName,
        [bool]$PreserveData = $true,
        [bool]$PreserveEnv = $true
    )

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Step ("Stopping existing service: {0}" -f $ServiceName)
        try {
            if ($existingService.Status -ne "Stopped") {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            }
        } catch {
            Write-Warning ("Failed to stop service {0}: {1}" -f $ServiceName, $_.Exception.Message)
        }

        Start-Sleep -Seconds 2

        Write-Step ("Removing Windows service: {0}" -f $ServiceName)
        try {
            & sc.exe delete $ServiceName | Out-Null
        } catch {
            Write-Warning ("Failed to delete service {0} via sc.exe: {1}" -f $ServiceName, $_.Exception.Message)
        }
    }

    $cleanupTargets = @(
        ".venv",
        "logs",
        "tools\\nssm"
    )

    if (-not $PreserveData) {
        $cleanupTargets += "data"
    }

    if (-not $PreserveEnv) {
        $cleanupTargets += ".env"
    }

    foreach ($relativePath in $cleanupTargets) {
        $absolutePath = Join-Path $RootPath $relativePath
        if (Test-Path -LiteralPath $absolutePath) {
            Write-Step ("Removing previous {0}" -f $relativePath)
            try {
                Remove-Item -Path $absolutePath -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Warning ("Failed to remove {0}: {1}" -f $absolutePath, $_.Exception.Message)
            }
        }
    }
}

Assert-Admin

$InstallRoot = Resolve-AbsolutePath -Path $InstallRoot
if (-not $InstallRoot) {
    throw "InstallRoot could not be resolved."
}

$SelectedMode = Select-DeploymentMode -Mode $DeploymentMode
Write-Step ("部署模式: {0}" -f $SelectedMode)

Enter-DeletionSafeLocation -TargetPath $InstallRoot

$ToolsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerDir = if ($ToolsDir) { Split-Path -Parent $ToolsDir } else { $null }

$InstallRootNormalized = [System.IO.Path]::GetFullPath($InstallRoot)
$ServerDirNormalized = if ($ServerDir) { [System.IO.Path]::GetFullPath($ServerDir) } else { $null }
$InstallRootIsSource = $false
if ($ServerDirNormalized) {
    $InstallRootIsSource = ($InstallRootNormalized.TrimEnd('\') -ieq $ServerDirNormalized.TrimEnd('\'))
}

$ExistingEnv = @{}

switch ($SelectedMode) {
    "Fresh" {
        Write-Step "执行全新部署：将移除现有服务、环境与数据"
        Cleanup-PreviousDeployment -RootPath $InstallRoot -ServiceName $ServiceName -PreserveData:$false -PreserveEnv:$false
        if ($InstallRootIsSource) {
            Write-Step "检测到安装目录与源码目录相同，仅清理运行时资产，保留源文件"
        } elseif (Test-Path -LiteralPath $InstallRoot) {
            Enter-DeletionSafeLocation -TargetPath $InstallRoot
            Write-Step ("删除旧的安装目录: {0}" -f $InstallRoot)
            try {
                Remove-Item -Path $InstallRoot -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Warning ("删除安装目录失败：{0}" -f $_.Exception.Message)
            }
            if (Test-Path -LiteralPath $InstallRoot) {
                throw ("无法删除安装目录 {0}，请确认没有程序正在使用该路径后重试。" -f $InstallRoot)
            }
        }
        if (-not (Test-Path -LiteralPath $InstallRoot)) {
            Write-Step ("创建安装目录: {0}" -f $InstallRoot)
            New-Item -ItemType Directory -Path $InstallRoot | Out-Null
        }
    }
    "Upgrade" {
        Write-Step "执行升级部署：保留 data/.env，仅重建运行环境"
        Cleanup-PreviousDeployment -RootPath $InstallRoot -ServiceName $ServiceName -PreserveData:$true -PreserveEnv:$true
        if (-not (Test-Path -LiteralPath $InstallRoot)) {
            Write-Step ("创建安装目录: {0}" -f $InstallRoot)
            New-Item -ItemType Directory -Path $InstallRoot | Out-Null
        }
    }
    "Uninstall" {
        Write-Step "执行卸载：停止服务并移除所有文件"
        Cleanup-PreviousDeployment -RootPath $InstallRoot -ServiceName $ServiceName -PreserveData:$false -PreserveEnv:$false
        if ($InstallRootIsSource) {
            Write-Warning "检测到安装目录与源码目录相同，将保留源文件，仅停止服务并清理运行时资产。"
        } elseif (Test-Path -LiteralPath $InstallRoot) {
            Enter-DeletionSafeLocation -TargetPath $InstallRoot
            Write-Step ("删除安装目录: {0}" -f $InstallRoot)
            try {
                Remove-Item -Path $InstallRoot -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Warning ("删除安装目录失败：{0}" -f $_.Exception.Message)
            }
            if (Test-Path -LiteralPath $InstallRoot) {
                throw ("无法删除安装目录 {0}，请确认没有程序正在使用该路径后重试。" -f $InstallRoot)
            }
        }
        Write-Step "卸载流程已完成，脚本退出。"
        return
    }
    default {
        throw "Unknown deployment mode: $SelectedMode"
    }
}

$EnvFile = Join-Path $InstallRoot ".env"
if (Test-Path -LiteralPath $EnvFile) {
    $ExistingEnv = Get-EnvMap -FilePath $EnvFile
}

if (-not (Test-Path -LiteralPath $InstallRoot)) {
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

if (-not $ExistingEnv) {
    $ExistingEnv = Get-EnvMap -FilePath $EnvFile
}

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

$NormalizedSlotCode = if ([string]::IsNullOrWhiteSpace($SlotCode)) { "default-slot" } else { $SlotCode.Trim().ToLower() }
$SlotSecretSource = "generated"
$EffectiveSlotSecret = $null
if ($PSBoundParameters.ContainsKey("SlotSecret")) {
    if ([string]::IsNullOrWhiteSpace($SlotSecret)) {
        throw "-SlotSecret cannot be empty. Omit the parameter to auto-generate a value."
    }
    if ($SlotSecret.Trim().Length -lt 16) {
        throw "-SlotSecret must be at least 16 characters long."
    }
    $EffectiveSlotSecret = $SlotSecret.Trim()
    $SlotSecretSource = "parameter"
} else {
    $EffectiveSlotSecret = New-RandomToken -Bytes 36
}

$monitorEnabledSource = "default"
$existingMonitorEnabled = $null
if ($ExistingEnv.ContainsKey("VMP_CDN_HEALTH_MONITOR_ENABLED")) {
    try {
        $existingMonitorEnabled = ConvertTo-NullableBoolean -Value $ExistingEnv["VMP_CDN_HEALTH_MONITOR_ENABLED"]
    } catch {
        Write-Warning ("Unable to parse existing VMP_CDN_HEALTH_MONITOR_ENABLED value: {0}" -f $ExistingEnv["VMP_CDN_HEALTH_MONITOR_ENABLED"])
    }
}

$FinalMonitorEnabled = $true

if ($PSBoundParameters.ContainsKey("MonitorEnabled")) {
    try {
        $parsedMonitorEnabled = ConvertTo-NullableBoolean -Value $MonitorEnabled
    } catch {
        throw "Invalid value supplied for -MonitorEnabled. Use true/false/1/0/yes/no/on/off."
    }

    if ($null -eq $parsedMonitorEnabled) {
        if ($null -ne $existingMonitorEnabled) {
            $FinalMonitorEnabled = [bool]$existingMonitorEnabled
            $monitorEnabledSource = "parameter-fallback-existing"
        } else {
            $FinalMonitorEnabled = $true
            $monitorEnabledSource = "parameter-default"
        }
    } else {
        $FinalMonitorEnabled = [bool]$parsedMonitorEnabled
        $monitorEnabledSource = "parameter"
    }
} elseif ($null -ne $existingMonitorEnabled) {
    $FinalMonitorEnabled = [bool]$existingMonitorEnabled
    $monitorEnabledSource = "existing"
}
$FinalEnv["VMP_CDN_HEALTH_MONITOR_ENABLED"] = if ($FinalMonitorEnabled) { "true" } else { "false" }

$monitorIntervalSource = "default"
if ($PSBoundParameters.ContainsKey("MonitorIntervalSeconds")) {
    $FinalMonitorInterval = $MonitorIntervalSeconds
    $monitorIntervalSource = "parameter"
} else {
    $FinalMonitorInterval = $MonitorIntervalSeconds
    if ($ExistingEnv.ContainsKey("VMP_CDN_HEALTH_MONITOR_INTERVAL")) {
        $existingIntervalRaw = $ExistingEnv["VMP_CDN_HEALTH_MONITOR_INTERVAL"]
        if (-not [string]::IsNullOrWhiteSpace($existingIntervalRaw)) {
            $parsedInterval = 0
            if ([int]::TryParse($existingIntervalRaw, [ref]$parsedInterval)) {
                $FinalMonitorInterval = $parsedInterval
                $monitorIntervalSource = "existing"
            }
        }
    }
}
$FinalMonitorInterval = [Math]::Min([Math]::Max([int]$FinalMonitorInterval, 30), 3600)
$FinalEnv["VMP_CDN_HEALTH_MONITOR_INTERVAL"] = $FinalMonitorInterval

$finalHealthCheckPort = $null
$healthPortSource = "default"
if ($PSBoundParameters.ContainsKey("CdnHealthCheckPort")) {
    $finalHealthCheckPort = [int]$CdnHealthCheckPort
    $healthPortSource = "parameter"
} elseif ($ExistingEnv.ContainsKey("VMP_CDN_HEALTH_CHECK_PORT")) {
    $existingHealthPortRaw = $ExistingEnv["VMP_CDN_HEALTH_CHECK_PORT"]
    if (-not [string]::IsNullOrWhiteSpace($existingHealthPortRaw)) {
        $parsedHealthPort = 0
        if ([int]::TryParse($existingHealthPortRaw, [ref]$parsedHealthPort)) {
            $finalHealthCheckPort = $parsedHealthPort
            $healthPortSource = "existing"
        }
    }
}

if (-not $finalHealthCheckPort) {
    $finalHealthCheckPort = [int]$Port
    if ($healthPortSource -eq "default") {
        $healthPortSource = "fallback-port"
    }
}

$FinalEnv["VMP_CDN_HEALTH_CHECK_PORT"] = $finalHealthCheckPort

$FinalEnv["VMP_CDN_IP_HEADER"] = if ($ExistingEnv.ContainsKey("VMP_CDN_IP_HEADER") -and -not [string]::IsNullOrWhiteSpace($ExistingEnv["VMP_CDN_IP_HEADER"])) {
    $ExistingEnv["VMP_CDN_IP_HEADER"].Trim()
} else {
    "X-Forwarded-For"
}

$cdnWhitelistRaw = if ($ExistingEnv.ContainsKey("VMP_CDN_IP_WHITELIST")) { $ExistingEnv["VMP_CDN_IP_WHITELIST"] } else { "" }
if ($cdnWhitelistRaw -match "203\.0\.113\.10" -and $cdnWhitelistRaw -match "203\.0\.113\.11") {
    $cdnWhitelistRaw = ""
}
$cdnWhitelistInfo = Get-AccessListInfo -Value $cdnWhitelistRaw
$FinalEnv["VMP_CDN_IP_WHITELIST"] = $cdnWhitelistInfo.Value

$cdnManualRaw = if ($ExistingEnv.ContainsKey("VMP_CDN_IP_MANUAL_WHITELIST")) { $ExistingEnv["VMP_CDN_IP_MANUAL_WHITELIST"] } else { "" }
$cdnManualInfo = Get-AccessListInfo -Value $cdnManualRaw
$FinalEnv["VMP_CDN_IP_MANUAL_WHITELIST"] = $cdnManualInfo.Value

$cdnBlacklistRaw = if ($ExistingEnv.ContainsKey("VMP_CDN_IP_BLACKLIST")) { $ExistingEnv["VMP_CDN_IP_BLACKLIST"] } else { "" }
$cdnBlacklistInfo = Get-AccessListInfo -Value $cdnBlacklistRaw
$FinalEnv["VMP_CDN_IP_BLACKLIST"] = $cdnBlacklistInfo.Value

$FinalEnv["VMP_CORE_IP_HEADER"] = if ($ExistingEnv.ContainsKey("VMP_CORE_IP_HEADER") -and $ExistingEnv["VMP_CORE_IP_HEADER"]) {
    $ExistingEnv["VMP_CORE_IP_HEADER"].Trim()
} else {
    ""
}

$coreWhitelistRaw = if ($ExistingEnv.ContainsKey("VMP_CORE_IP_WHITELIST")) { $ExistingEnv["VMP_CORE_IP_WHITELIST"] } else { "" }
$coreWhitelistInfo = Get-AccessListInfo -Value $coreWhitelistRaw
$FinalEnv["VMP_CORE_IP_WHITELIST"] = $coreWhitelistInfo.Value

$coreBlacklistRaw = if ($ExistingEnv.ContainsKey("VMP_CORE_IP_BLACKLIST")) { $ExistingEnv["VMP_CORE_IP_BLACKLIST"] } else { "" }
$coreBlacklistInfo = Get-AccessListInfo -Value $coreBlacklistRaw
$FinalEnv["VMP_CORE_IP_BLACKLIST"] = $coreBlacklistInfo.Value

$accessSummary = [PSCustomObject]@{
    CdnAuto      = $cdnWhitelistInfo
    CdnManual    = $cdnManualInfo
    CdnBlacklist = $cdnBlacklistInfo
    CoreWhitelist = $coreWhitelistInfo
    CoreBlacklist = $coreBlacklistInfo
}

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

switch ($monitorEnabledSource) {
    "parameter" { Write-Host ("    VMP_CDN_HEALTH_MONITOR_ENABLED set from parameter ({0})" -f $FinalEnv["VMP_CDN_HEALTH_MONITOR_ENABLED"]) -ForegroundColor Yellow }
    "parameter-fallback-existing" { Write-Host ("    VMP_CDN_HEALTH_MONITOR_ENABLED = {0} (parameter left blank, existing value preserved)" -f $FinalEnv["VMP_CDN_HEALTH_MONITOR_ENABLED"]) }
    "parameter-default" { Write-Host ("    VMP_CDN_HEALTH_MONITOR_ENABLED = {0} (parameter left blank, default applied)" -f $FinalEnv["VMP_CDN_HEALTH_MONITOR_ENABLED"]) }
    "existing" { Write-Host ("    VMP_CDN_HEALTH_MONITOR_ENABLED = {0} (existing value preserved)" -f $FinalEnv["VMP_CDN_HEALTH_MONITOR_ENABLED"]) }
    default { Write-Host ("    VMP_CDN_HEALTH_MONITOR_ENABLED = {0}" -f $FinalEnv["VMP_CDN_HEALTH_MONITOR_ENABLED"]) }
}

switch ($monitorIntervalSource) {
    "parameter" { Write-Host ("    VMP_CDN_HEALTH_MONITOR_INTERVAL set from parameter ({0}s)" -f $FinalMonitorInterval) -ForegroundColor Yellow }
    "existing" { Write-Host ("    VMP_CDN_HEALTH_MONITOR_INTERVAL = {0}s (existing value preserved)" -f $FinalMonitorInterval) }
    default { Write-Host ("    VMP_CDN_HEALTH_MONITOR_INTERVAL = {0}s" -f $FinalMonitorInterval) }
}

switch ($healthPortSource) {
    "parameter" { Write-Host ("    VMP_CDN_HEALTH_CHECK_PORT set from parameter ({0})" -f $finalHealthCheckPort) -ForegroundColor Yellow }
    "existing" { Write-Host ("    VMP_CDN_HEALTH_CHECK_PORT = {0} (existing value preserved)" -f $finalHealthCheckPort) }
    "fallback-port" { Write-Host ("    VMP_CDN_HEALTH_CHECK_PORT = {0} (defaulted to service port)" -f $finalHealthCheckPort) }
    default { Write-Host ("    VMP_CDN_HEALTH_CHECK_PORT = {0}" -f $finalHealthCheckPort) }
}

$cdnHeaderDisplay = if ([string]::IsNullOrWhiteSpace($FinalEnv["VMP_CDN_IP_HEADER"])) { "<connection-ip>" } else { $FinalEnv["VMP_CDN_IP_HEADER"] }
$coreHeaderDisplay = if ([string]::IsNullOrWhiteSpace($FinalEnv["VMP_CORE_IP_HEADER"])) { "<connection-ip>" } else { $FinalEnv["VMP_CORE_IP_HEADER"] }
Write-Host ("    VMP_CDN_IP_HEADER = {0}" -f $cdnHeaderDisplay)
Write-Host ("    VMP_CORE_IP_HEADER = {0}" -f $coreHeaderDisplay)
Write-Host ("    CDN 自动白名单条目：{0}" -f $accessSummary.CdnAuto.Count)
Write-Host ("    CDN 手动白名单条目：{0}" -f $accessSummary.CdnManual.Count)
Write-Host ("    CDN 黑名单条目：{0}" -f $accessSummary.CdnBlacklist.Count)
Write-Host ("    主服务白名单条目：{0}" -f $accessSummary.CoreWhitelist.Count)
Write-Host ("    主服务黑名单条目：{0}" -f $accessSummary.CoreBlacklist.Count)
Write-Host "    自动拉黑已启用：异常访问的 IP 会自动追加到对应黑名单，并同步到后台『访问控制』页面。" -ForegroundColor Yellow

Write-Step "Initializing SQLite database (includes Alembic migrations)"
$ManagePy = Join-Path $ServerDir "manage.py"
if (-not (Test-Path -LiteralPath $ManagePy)) {
    throw "manage.py was not found in the server directory."
}
& $VenvPython $ManagePy init-db
Write-Host "    CDN deployment schema synced (stage timelines & rollback chain ready)."

Write-Step ("Applying slot secret for '{0}'" -f $NormalizedSlotCode)
$slotArgs = @("set-slot-secret", $NormalizedSlotCode, "--secret", $EffectiveSlotSecret)
$slotOutput = & $VenvPython $ManagePy @slotArgs 2>&1
$slotExitCode = $LASTEXITCODE
if ($slotExitCode -eq 0) {
    foreach ($line in $slotOutput) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Host ("    {0}" -f $line.Trim())
        }
    }
    if ($SlotSecretSource -eq "parameter") {
        Write-Host "    Slot secret applied from -SlotSecret parameter." -ForegroundColor Yellow
    } else {
        Write-Host ("    Generated slot secret (store securely): {0}" -f $EffectiveSlotSecret) -ForegroundColor Yellow
    }
} else {
    Write-Warning ("    Failed to set slot secret for '{0}'." -f $NormalizedSlotCode)
    if ($slotOutput) {
        foreach ($line in $slotOutput) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                Write-Warning ("      {0}" -f $line.Trim())
            }
        }
    }
    Write-Warning "    Please use 'python manage.py set-slot-secret <slot-code>' manually after deployment."
    if ($SlotSecretSource -ne "parameter") {
        Write-Host ("    Generated slot secret (not applied): {0}" -f $EffectiveSlotSecret) -ForegroundColor Yellow
    }
}

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
    Expand-ZipArchiveCompat -ZipPath $TempZip -DestinationPath $TempDir
    $Candidate = Get-ChildItem -Path $TempDir -Recurse -Filter "nssm.exe" | Where-Object { $_.FullName -match "win64" } | Select-Object -First 1
    if (-not $Candidate) {
        throw "win64 nssm.exe was not found inside the archive."
    }
    Copy-Item -Path $Candidate.FullName -Destination $NssmExe -Force
    Remove-Item -Path $TempZip -Force
    Remove-Item -Path $TempDir -Recurse -Force
}

function Invoke-Nssm {
    param(
        [string[]]$Arguments,
        [int[]]$AllowedExitCodes = @(0)
    )

    $process = Start-Process -FilePath $NssmExe -ArgumentList $Arguments -NoNewWindow -Wait -PassThru
    if (-not ($AllowedExitCodes -contains $process.ExitCode)) {
        $joinedArgs = $Arguments -join ' '
        throw ("NSSM command failed (exit {1}): {0}" -f $joinedArgs, $process.ExitCode)
    }

    return $process.ExitCode
}

function Get-NssmStateName {
    param([int]$StatusCode)

    switch ($StatusCode) {
        0 { return "SERVICE_RUNNING" }
        1 { return "SERVICE_STOPPED" }
        2 { return "SERVICE_START_PENDING" }
        3 { return "SERVICE_STOP_PENDING" }
        4 { return "SERVICE_CONTINUE_PENDING" }
        5 { return "SERVICE_PAUSE_PENDING" }
        6 { return "SERVICE_PAUSED" }
        default { return "UNKNOWN" }
    }
}

function Wait-NssmServiceRunning {
    param(
        [string]$ServiceName,
        [int]$TimeoutSeconds = 60,
        [string]$LogHint
    )

    $elapsed = 0
    $pollInterval = 2
    while ($elapsed -le $TimeoutSeconds) {
        $statusCode = Invoke-Nssm -Arguments @("status", $ServiceName) -AllowedExitCodes @(0,1,2,3,4,5,6)
        $state = Get-NssmStateName -StatusCode $statusCode
        if ($state -eq "SERVICE_RUNNING") {
            return
        }
        if ($state -eq "SERVICE_STOPPED") {
            $message = "Service {0} stopped immediately after start (status: {1})." -f $ServiceName, $state
            if ($LogHint) {
                $message += " Check logs under " + $LogHint + "."
            }
            throw $message
        }

        Start-Sleep -Seconds $pollInterval
        $elapsed += $pollInterval
    }

    $finalStatusCode = Invoke-Nssm -Arguments @("status", $ServiceName) -AllowedExitCodes @(0,1,2,3,4,5,6)
    $finalState = Get-NssmStateName -StatusCode $finalStatusCode
    $timeoutMessage = "Service {0} did not reach RUNNING within {1}s (last status: {2})." -f $ServiceName, $TimeoutSeconds, $finalState
    if ($LogHint) {
        $timeoutMessage += " Check logs under " + $LogHint + "."
    }
    throw $timeoutMessage
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
if ($existingRule) {
    try {
        Write-Step "Updating existing firewall rule to match new port"
        Remove-NetFirewallRule -DisplayName $FirewallName -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning ("Failed to remove existing firewall rule '{0}': {1}" -f $FirewallName, $_.Exception.Message)
    }
}
New-NetFirewallRule -DisplayName $FirewallName -Direction Inbound -Profile Any -Action Allow -Protocol TCP -LocalPort $Port | Out-Null

Write-Step "Starting service"
$startExitCode = Invoke-Nssm -Arguments @("start", $ServiceName) -AllowedExitCodes @(0,1,2,3,4,5,6)
$startState = Get-NssmStateName -StatusCode $startExitCode
Write-Host (" NSSM start exit: {0} ({1})" -f $startExitCode, $startState)
Wait-NssmServiceRunning -ServiceName $ServiceName -TimeoutSeconds 60 -LogHint $LogsPath

$BaseUrl = "http://{0}:{1}" -f $ListenHost, $Port
Write-Step ("Deployment finished. Listening on {0}" -f $BaseUrl)

$DisplayUrl = $BaseUrl
if ($ListenHost -eq "0.0.0.0" -or $ListenHost -eq "::") {
    $DisplayUrl = "http://<server-ip>:{0}" -f $Port
    Write-Host " Bound to all interfaces; replace <server-ip> with the machine's address when accessing remotely." -ForegroundColor Yellow
}

$HealthUrl = "http://127.0.0.1:{0}/api/v1/ping" -f $Port
try {
    $health = Invoke-RestMethod -Uri $HealthUrl -Method Get -TimeoutSec 5
    if ($health -and $health.message -eq "pong") {
        Write-Host (" Health check: {0} -> {1}" -f $HealthUrl, $health.message) -ForegroundColor Green
    } else {
        Write-Host (" Health check returned unexpected payload from {0}" -f $HealthUrl) -ForegroundColor Yellow
    }
} catch {
    Write-Host (" Health check failed for {0}: {1}" -f $HealthUrl, $_.Exception.Message) -ForegroundColor Yellow
}

Write-Host ""
Write-Host (" Admin dashboard: {0}/admin/" -f $DisplayUrl) -ForegroundColor Green
Write-Host (" Admin portal (licenses): {0}/admin/licenses" -f $DisplayUrl) -ForegroundColor Green
Write-Host (" Software slots: {0}/admin/software" -f $DisplayUrl) -ForegroundColor Green
Write-Host "  · 部署后可在后台查看/复制 slot secret，亦可使用 manage.py CLI 快速导出或重置。" -ForegroundColor Yellow
Write-Host "  · 示例：python manage.py list-slots / python manage.py rotate-slot-secret <slot-code>" -ForegroundColor Yellow
Write-Host "  · 自定义密钥：python manage.py set-slot-secret <slot-code> --secret <value>" -ForegroundColor Yellow
Write-Host (" CDN management: {0}/admin/cdn" -f $DisplayUrl) -ForegroundColor Green
Write-Host "  · 查看最新部署阶段日志与一键回滚工具" -ForegroundColor Yellow
$CdnConfigExample = if ($ServerDir) { Join-Path $ServerDir "tools\cdn_deploy_config.example.json" } else { $null }
if ($CdnConfigExample -and (Test-Path -LiteralPath $CdnConfigExample)) {
    Write-Host ("  · 多端口映射：编辑 {0} 的 port_mappings 数组或在后台端口映射表中增删行" -f $CdnConfigExample) -ForegroundColor Yellow
} else {
    Write-Host "  · 多端口映射：在后台端口映射表中增删行，CLI 同步时请参考 repo/tools/cdn_deploy_config.example.json" -ForegroundColor Yellow
}
Write-Host "  · edge_token 将在部署与回滚流程中自动去除前后空白，便于直接粘贴脚本输出的共享密钥" -ForegroundColor Yellow
Write-Host (" Access control panel: {0}/admin/settings" -f $DisplayUrl) -ForegroundColor Green
$accessStatsMessage = "  · 访问控制当前统计：CDN 自动 $($accessSummary.CdnAuto.Count) / 手动 $($accessSummary.CdnManual.Count) / 黑名单 $($accessSummary.CdnBlacklist.Count)，主服务白名单 $($accessSummary.CoreWhitelist.Count) / 黑名单 $($accessSummary.CoreBlacklist.Count)"
Write-Host $accessStatsMessage -ForegroundColor Yellow
Write-Host '  · 通过后台“系统设置 → 访问控制”卡片维护名单，保存后将即时写回 .env 并在下次部署时继续保留。' -ForegroundColor Yellow
Write-Host (" Users portal: {0}/admin/users" -f $DisplayUrl) -ForegroundColor Green
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
