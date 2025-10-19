from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import posixpath
import re
from typing import Iterable, Optional

import paramiko

EDGE_CONFIG_REMOTE_PATH = "/etc/nginx/conf.d/vmp_edge.conf"
DEFAULT_SSL_CERT = "/etc/pki/tls/certs/edge.crt"
DEFAULT_SSL_KEY = "/etc/pki/tls/private/edge.key"


class DeploymentError(RuntimeError):
    """Raised when deploying to an edge node fails."""

    def __init__(self, message: str, *, log: Optional[str] = None) -> None:
        super().__init__(message)
        self.log = log or ""


@dataclass
class DeploymentTarget:
    name: str
    host: str
    username: str
    port: int = 22
    password: Optional[str] = None
    private_key: Optional[str] = None
    sudo_password: Optional[str] = None


@dataclass
class DeploymentConfig:
    origin_host: str
    origin_port: int = 443
    listen_port: int = 443
    edge_token: Optional[str] = None
    mode: str = "http"
    allow_http: bool = False
    proxy_protocol: bool = False
    ssl_certificate: Optional[str] = None
    ssl_certificate_key: Optional[str] = None
    extra_packages: list[str] = field(default_factory=lambda: ["nginx"])
    firewall_ports: list[int] = field(default_factory=lambda: [80, 443])

    def normalize(self) -> None:
        if self.mode not in {"http", "tcp"}:
            raise ValueError("deployment_mode_invalid")
        if self.listen_port <= 0 or self.origin_port <= 0:
            raise ValueError("port_invalid")
        if not self.origin_host:
            raise ValueError("origin_required")
        if self.proxy_protocol and self.mode != "tcp":
            self.proxy_protocol = False


@dataclass
class DeploymentResult:
    started_at: datetime
    completed_at: datetime
    log: str
    summary: str

    @property
    def duration_ms(self) -> int:
        return int((self.completed_at - self.started_at).total_seconds() * 1000)


def generate_nginx_config(config: DeploymentConfig) -> str:
    config.normalize()

    if config.mode == "tcp":
        listen_line = f"        listen {config.listen_port}"
        if config.proxy_protocol:
            listen_line += " proxy_protocol;"
        else:
            listen_line += ";"

        stream_block = [
            "stream {",
            "    upstream vmp_origin {",
            f"        server {config.origin_host}:{config.origin_port};",
            "    }",
            "",
            "    server {",
            listen_line,
            "        proxy_connect_timeout 5s;",
            "        proxy_timeout 300s;",
            "        proxy_pass vmp_origin;",
        ]
        if config.proxy_protocol:
            stream_block.append("        proxy_protocol on;")
        stream_block.extend(
            [
                "    }",
                "}",
            ]
        )
        return "\n".join(stream_block) + "\n"

    listen_directives: list[str] = []
    tls_enabled = _is_tls_enabled(config)

    if config.allow_http and (not tls_enabled or config.listen_port != 80):
        listen_directives.append("    listen 80;")

    if tls_enabled:
        listen_directives.append(f"    listen {config.listen_port} ssl;")
    else:
        if not (config.allow_http and config.listen_port == 80):
            listen_directives.append(f"    listen {config.listen_port};")

    header_lines = [
        "        proxy_set_header Host {host};".format(host=config.origin_host),
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
    ]
    if config.edge_token:
        header_lines.append(f"        proxy_set_header X-Edge-Token \"{config.edge_token}\";")

    cache_directives = [
        "proxy_cache_path /var/cache/nginx/vmp levels=1:2 keys_zone=vmp_cache:10m max_size=1g inactive=10m use_temp_path=off;",
        "",
    ]

    config_block = [
        *cache_directives,
        "server {",
        *listen_directives,
    ]

    if tls_enabled:
        ssl_cert = config.ssl_certificate or DEFAULT_SSL_CERT
        ssl_key = config.ssl_certificate_key or DEFAULT_SSL_KEY
        config_block.extend(
            [
                "    http2 on;",
                f"    ssl_certificate {ssl_cert};",
                f"    ssl_certificate_key {ssl_key};",
                "    ssl_protocols TLSv1.2 TLSv1.3;",
                "    ssl_ciphers HIGH:!aNULL:!MD5;",
            ]
        )

    config_block.extend(
        [
            "    server_name _;",
            "",
            "    proxy_buffering on;",
            "",
            "    location / {",
            f"        proxy_pass https://{config.origin_host}:{config.origin_port};",
            *header_lines,
            "        proxy_cache vmp_cache;",
            "        proxy_cache_valid 200 302 10m;",
            "        proxy_cache_valid 404 1m;",
            "        add_header X-Cache-Status $upstream_cache_status always;",
            "    }",
            "}",
        ]
    )
    return "\n".join(config_block) + "\n"


def _is_tls_enabled(config: DeploymentConfig) -> bool:
    if config.mode != "http":
        return False
    if config.listen_port == 80 and not (config.ssl_certificate or config.ssl_certificate_key):
        return False
    return True


def _connect(target: DeploymentTarget) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=target.host,
        port=target.port,
        username=target.username,
        password=target.password,
        key_filename=target.private_key,
        timeout=20,
    )
    return ssh


def _run_command(
    ssh: paramiko.SSHClient,
    command: str,
    *,
    sudo_password: Optional[str] = None,
) -> str:
    sanitized = command.strip()
    requires_sudo = sanitized.startswith("sudo ")
    executed_command = command
    if requires_sudo:
        executed_command = command.replace("sudo ", "sudo -S -p '' ", 1)
    stdin, stdout, stderr = ssh.exec_command(executed_command, get_pty=requires_sudo)
    if requires_sudo and sudo_password:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    exit_status = stdout.channel.recv_exit_status()
    stdout_output = stdout.read().decode("utf-8", errors="ignore").strip()
    stderr_output = stderr.read().decode("utf-8", errors="ignore").strip()
    if exit_status != 0:
        error_output = stderr_output or stdout_output
        raise DeploymentError(f"Command failed ({exit_status}): {command}\n{error_output}")
    return stdout_output


def _append_log(log: list[str], message: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    log.append(f"[{timestamp}] {message}")


def _should_retry_with_vault(error_output: str) -> bool:
    lowered = error_output.lower()
    return (
        "mirrorlist.centos.org" in lowered
        or "cannot find a valid baseurl" in lowered
        or ("no package" in lowered and "nginx" in lowered)
        or "error: nothing to do" in lowered
    )


def _configure_centos_vault_repo(
    ssh: paramiko.SSHClient,
    *,
    sudo_password: Optional[str] = None,
) -> None:
    try:
        release_info = _run_command(ssh, "cat /etc/centos-release")
    except DeploymentError:
        release_info = ""

    match = re.search(r"(\d+\.\d+\.\d+)", release_info)
    if match:
        release_version = match.group(1)
    else:
        release_version = "7.9.2009"

    major_version = release_version.split(".")[0]

    repo_text = f"""[centos-vault-base]
name=CentOS {release_version} - Vault - Base
baseurl=https://vault.centos.org/{release_version}/os/$basearch/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-{major_version}

[centos-vault-updates]
name=CentOS {release_version} - Vault - Updates
baseurl=https://vault.centos.org/{release_version}/updates/$basearch/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-{major_version}

[nginx-stable]
name=Nginx Stable Repository
baseurl=http://nginx.org/packages/centos/{major_version}/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
"""

    _upload_config(
        ssh,
        repo_text,
        "/etc/yum.repos.d/CentOS-Vault.repo",
        sudo_password=sudo_password,
    )

    disable_commands = [
        "sudo sed -i 's/^enabled=1/enabled=0/g' /etc/yum.repos.d/CentOS-Base.repo",
        "sudo sed -i 's/^enabled=1/enabled=0/g' /etc/yum.repos.d/CentOS-Updates.repo",
        "sudo sed -i 's/^enabled=1/enabled=0/g' /etc/yum.repos.d/CentOS-Extras.repo",
    ]
    for command in disable_commands:
        try:
            _run_command(ssh, command, sudo_password=sudo_password)
        except DeploymentError as exc:
            if "no such file or directory" in str(exc).lower():
                continue
            raise

    _run_command(
        ssh,
        "sudo rpm --import https://nginx.org/keys/nginx_signing.key",
        sudo_password=sudo_password,
    )
    _run_command(ssh, "sudo yum clean all", sudo_password=sudo_password)
    _run_command(ssh, "sudo yum makecache", sudo_password=sudo_password)


def _cleanup_previous_deployment(
    ssh: paramiko.SSHClient,
    *,
    sudo_password: Optional[str] = None,
    log: Optional[list[str]] = None,
) -> None:
    def _run_ignoring_failure(command: str) -> None:
        try:
            _run_command(ssh, command, sudo_password=sudo_password)
        except DeploymentError:
            return

    if log is not None:
        _append_log(log, "执行部署前清理任务")

    _run_ignoring_failure("sudo systemctl stop nginx")
    _run_ignoring_failure(f"sudo rm -f {EDGE_CONFIG_REMOTE_PATH}")
    _run_ignoring_failure("sudo rm -rf /var/run/nginx.pid")
    _run_ignoring_failure("sudo rm -rf /var/run/nginx")
    _run_ignoring_failure("sudo rm -rf /var/cache/nginx/vmp")
    _run_ignoring_failure("sudo mkdir -p /var/cache/nginx")

    if log is not None:
        _append_log(log, "预清理完成")


def _prepare_nginx_runtime(
    ssh: paramiko.SSHClient,
    *,
    sudo_password: Optional[str] = None,
) -> None:
    commands = [
        "sudo mkdir -p /var/cache/nginx/vmp",
        "sudo chown -R nginx:nginx /var/cache/nginx",
        "sudo mkdir -p /var/run/nginx",
        "sudo chown root:root /var/run/nginx",
        "sudo chmod 755 /var/run/nginx",
    ]
    for command in commands:
        _run_command(ssh, command, sudo_password=sudo_password)
    try:
        _run_command(ssh, "sudo restorecon -RF /var/run/nginx", sudo_password=sudo_password)
    except DeploymentError:
        # SELinux may be disabled or restorecon unavailable; ignore in that case.
        pass


def _ensure_ssl_assets(
    ssh: paramiko.SSHClient,
    *,
    cert_path: str,
    key_path: str,
    sudo_password: Optional[str] = None,
    log: Optional[list[str]] = None,
    generate_missing: bool = True,
) -> None:
    def _path_exists(path: str) -> bool:
        try:
            _run_command(ssh, f"sudo test -f {path}", sudo_password=sudo_password)
            return True
        except DeploymentError:
            return False

    cert_exists = _path_exists(cert_path)
    key_exists = _path_exists(key_path)
    if cert_exists and key_exists:
        return

    if not generate_missing:
        missing: list[str] = []
        if not cert_exists:
            missing.append(cert_path)
        if not key_exists:
            missing.append(key_path)
        raise DeploymentError(
            "SSL certificate or key not found on target host: " + ", ".join(missing)
        )

    if log is not None:
        _append_log(log, f"检测到缺少证书文件，正在生成自签名证书 ({cert_path})")

    for directory in {posixpath.dirname(cert_path), posixpath.dirname(key_path)}:
        if directory:
            _run_command(ssh, f"sudo mkdir -p {directory}", sudo_password=sudo_password)

    subj = "/CN=vmp-edge"
    _run_command(
        ssh,
        (
            "sudo openssl req -x509 -nodes -days 825 -newkey rsa:2048 "
            f"-subj '{subj}' -keyout {key_path} -out {cert_path}"
        ),
        sudo_password=sudo_password,
    )
    _run_command(ssh, f"sudo chmod 600 {key_path}", sudo_password=sudo_password)
    _run_command(ssh, f"sudo chmod 644 {cert_path}", sudo_password=sudo_password)
    if log is not None:
        _append_log(log, "已生成自签名证书")


def _install_packages(
    ssh: paramiko.SSHClient,
    packages: Iterable[str],
    *,
    sudo_password: Optional[str] = None,
    log: Optional[list[str]] = None,
) -> None:
    pkg_list = " ".join(packages)
    stdin, stdout, _ = ssh.exec_command("command -v dnf || command -v yum")
    manager = stdout.read().decode().strip()
    if not manager:
        raise DeploymentError("Unable to locate dnf or yum on target host")
    install_command = f"sudo {manager} -y install {pkg_list}"
    try:
        _run_command(ssh, install_command, sudo_password=sudo_password)
    except DeploymentError as exc:
        output = str(exc)
        if manager.endswith("yum") and _should_retry_with_vault(output):
            if log is not None:
                _append_log(log, "默认仓库不可达，尝试切换至 vault.centos.org")
            try:
                _configure_centos_vault_repo(ssh, sudo_password=sudo_password)
            except DeploymentError as repo_exc:
                raise DeploymentError(
                    f"Failed to switch to CentOS vault repository: {repo_exc}"
                ) from exc
            _run_command(ssh, install_command, sudo_password=sudo_password)
            if log is not None:
                _append_log(log, "已切换仓库并重新安装依赖")
        else:
            raise


def _configure_firewall(
    ssh: paramiko.SSHClient,
    ports: Iterable[int],
    *,
    sudo_password: Optional[str] = None,
) -> None:
    stdin, stdout, _ = ssh.exec_command("command -v firewall-cmd")
    if stdout.read().strip():
        for port in ports:
            _run_command(
                ssh,
                f"sudo firewall-cmd --permanent --add-port={port}/tcp",
                sudo_password=sudo_password,
            )
        _run_command(ssh, "sudo firewall-cmd --reload", sudo_password=sudo_password)


def _upload_config(
    ssh: paramiko.SSHClient,
    config_text: str,
    remote_path: str,
    *,
    sudo_password: Optional[str] = None,
) -> None:
    with ssh.open_sftp() as sftp:
        tmp_path = "/tmp/vmp_edge.conf"
        with sftp.file(tmp_path, "w") as remote_file:
            remote_file.write(config_text)
        _run_command(ssh, f"sudo mv {tmp_path} {remote_path}", sudo_password=sudo_password)
        _run_command(ssh, f"sudo chown root:root {remote_path}", sudo_password=sudo_password)


def _enable_services(
    ssh: paramiko.SSHClient,
    *,
    sudo_password: Optional[str] = None,
) -> None:
    _run_command(ssh, "sudo systemctl enable nginx", sudo_password=sudo_password)
    _run_command(ssh, "sudo nginx -t", sudo_password=sudo_password)
    try:
        _run_command(ssh, "sudo systemctl restart nginx", sudo_password=sudo_password)
    except DeploymentError as exc:
        diagnostics: list[str] = []

        def _collect(command: str) -> None:
            display = f"$ {command}"
            try:
                output = _run_command(ssh, command, sudo_password=sudo_password)
            except DeploymentError as cmd_exc:
                output = str(cmd_exc)
            diagnostics.append("\n".join([display, output]).rstrip())

        _collect("sudo systemctl status nginx --no-pager")
        _collect("sudo journalctl -u nginx -n 100 --no-pager")
        _collect("sudo ls -ld /var/run/nginx*")
        status_output = "\n\n".join(diagnostics)
        raise DeploymentError(
            f"Failed to restart nginx after config update. Original error: {exc}. Status output:\n{status_output}"
        ) from exc


class CDNDeployer:
    def __init__(self, remote_config_path: str = EDGE_CONFIG_REMOTE_PATH) -> None:
        self.remote_config_path = remote_config_path

    def deploy(self, target: DeploymentTarget, config: DeploymentConfig) -> DeploymentResult:
        config.normalize()
        config_text = generate_nginx_config(config)
        log_lines: list[str] = []
        started_at = datetime.now(timezone.utc)
        _append_log(log_lines, f"开始部署节点 {target.host}:{target.port} (模式: {config.mode})")

        ssh: Optional[paramiko.SSHClient] = None
        try:
            ssh = _connect(target)
        except Exception as exc:  # pragma: no cover - network dependent
            _append_log(log_lines, f"SSH 连接失败: {exc}")
            raise DeploymentError(f"Unable to connect to target host: {exc}", log="\n".join(log_lines)) from exc

        _append_log(log_lines, "SSH 连接已建立")
        try:
            _cleanup_previous_deployment(
                ssh,
                sudo_password=target.sudo_password,
                log=log_lines,
            )

            _append_log(log_lines, f"安装依赖软件包: {', '.join(config.extra_packages)}")
            _install_packages(
                ssh,
                config.extra_packages,
                sudo_password=target.sudo_password,
                log=log_lines,
            )
            _append_log(log_lines, "依赖安装完成")

            if config.mode == "http":
                tls_enabled = _is_tls_enabled(config)
                if tls_enabled:
                    ssl_cert_path = config.ssl_certificate or DEFAULT_SSL_CERT
                    ssl_key_path = config.ssl_certificate_key or DEFAULT_SSL_KEY
                    _ensure_ssl_assets(
                        ssh,
                        cert_path=ssl_cert_path,
                        key_path=ssl_key_path,
                        sudo_password=target.sudo_password,
                        log=log_lines,
                        generate_missing=not (config.ssl_certificate or config.ssl_certificate_key),
                    )

            _prepare_nginx_runtime(ssh, sudo_password=target.sudo_password)

            firewall_ports = sorted({*config.firewall_ports, config.listen_port})
            _append_log(log_lines, f"配置防火墙端口: {firewall_ports}")
            _configure_firewall(ssh, firewall_ports, sudo_password=target.sudo_password)
            _append_log(log_lines, "防火墙规则已更新")

            _append_log(log_lines, f"上传 Nginx 配置到 {self.remote_config_path}")
            _upload_config(
                ssh,
                config_text,
                self.remote_config_path,
                sudo_password=target.sudo_password,
            )
            _append_log(log_lines, "配置上传完成")

            _append_log(log_lines, "启用并重启 Nginx 服务")
            _enable_services(ssh, sudo_password=target.sudo_password)
            _append_log(log_lines, "Nginx 服务已重启")

            summary = "部署成功，Nginx 配置已刷新"
            completed_at = datetime.now(timezone.utc)
            _append_log(log_lines, summary)
            return DeploymentResult(
                started_at=started_at,
                completed_at=completed_at,
                log="\n".join(log_lines),
                summary=summary,
            )
        except DeploymentError as exc:
            _append_log(log_lines, f"部署失败: {exc}")
            merged_log = "\n".join(log_lines)
            if exc.log:
                merged_log = f"{exc.log}\n{merged_log}"
            exc.log = merged_log
            raise
        except Exception as exc:  # pragma: no cover - defensive
            _append_log(log_lines, f"部署出现未预期异常: {exc}")
            raise DeploymentError(f"Unexpected deployment error: {exc}", log="\n".join(log_lines)) from exc
        finally:
            if ssh is not None:
                ssh.close()


__all__ = [
    "CDNDeployer",
    "DeploymentConfig",
    "DeploymentError",
    "DeploymentResult",
    "DeploymentTarget",
    "EDGE_CONFIG_REMOTE_PATH",
    "generate_nginx_config",
]
