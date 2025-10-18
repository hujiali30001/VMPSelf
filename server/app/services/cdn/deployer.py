from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

import paramiko

EDGE_CONFIG_REMOTE_PATH = "/etc/nginx/conf.d/vmp_edge.conf"
DEFAULT_SSL_CERT = "/etc/pki/tls/certs/edge.crt"
DEFAULT_SSL_KEY = "/etc/pki/tls/private/edge.key"


class DeploymentError(RuntimeError):
    """Raised when deploying to an edge node fails."""


@dataclass
class DeploymentTarget:
    name: str
    host: str
    username: str
    port: int = 22
    password: Optional[str] = None
    private_key: Optional[str] = None


@dataclass
class DeploymentConfig:
    origin_host: str
    origin_port: int = 443
    listen_port: int = 443
    edge_token: Optional[str] = None
    mode: str = "http"
    allow_http: bool = False
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


def generate_nginx_config(config: DeploymentConfig) -> str:
    config.normalize()

    if config.mode == "tcp":
        stream_block = [
            "stream {",
            "    upstream vmp_origin {",
            f"        server {config.origin_host}:{config.origin_port};",
            "    }",
            "",
            "    server {",
            f"        listen {config.listen_port};",
            "        proxy_connect_timeout 5s;",
            "        proxy_timeout 300s;",
            "        proxy_pass vmp_origin;",
            "    }",
            "}",
        ]
        return "\n".join(stream_block) + "\n"

    listen_blocks: list[str] = []
    if config.allow_http:
        listen_blocks.append("    listen 80;")
    ssl_cert = config.ssl_certificate or DEFAULT_SSL_CERT
    ssl_key = config.ssl_certificate_key or DEFAULT_SSL_KEY
    listen_blocks.extend(
        [
            f"    listen {config.listen_port} ssl http2;",
            f"    ssl_certificate {ssl_cert};",
            f"    ssl_certificate_key {ssl_key};",
            "    ssl_protocols TLSv1.2 TLSv1.3;",
            "    ssl_ciphers HIGH:!aNULL:!MD5;",
        ]
    )

    header_lines = [
        "        proxy_set_header Host {host};".format(host=config.origin_host),
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
    ]
    if config.edge_token:
        header_lines.append(f"        proxy_set_header X-Edge-Token \"{config.edge_token}\";")

    config_block = [
        "server {",
        *listen_blocks,
        "    server_name _;",
        "",
        "    proxy_buffering on;",
        "    proxy_cache_path /var/cache/nginx/vmp levels=1:2 keys_zone=vmp_cache:10m max_size=1g inactive=10m use_temp_path=off;",
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
    return "\n".join(config_block) + "\n"


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


def _run_command(ssh: paramiko.SSHClient, command: str) -> None:
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        error_output = stderr.read().decode("utf-8", errors="ignore")
        raise DeploymentError(f"Command failed ({exit_status}): {command}\n{error_output}")


def _install_packages(ssh: paramiko.SSHClient, packages: Iterable[str]) -> None:
    pkg_list = " ".join(packages)
    stdin, stdout, _ = ssh.exec_command("command -v dnf || command -v yum")
    manager = stdout.read().decode().strip()
    if not manager:
        raise DeploymentError("Unable to locate dnf or yum on target host")
    _run_command(ssh, f"sudo {manager} -y install {pkg_list}")


def _configure_firewall(ssh: paramiko.SSHClient, ports: Iterable[int]) -> None:
    stdin, stdout, _ = ssh.exec_command("command -v firewall-cmd")
    if stdout.read().strip():
        for port in ports:
            _run_command(ssh, f"sudo firewall-cmd --permanent --add-port={port}/tcp")
        _run_command(ssh, "sudo firewall-cmd --reload")


def _upload_config(ssh: paramiko.SSHClient, config_text: str, remote_path: str) -> None:
    with ssh.open_sftp() as sftp:
        tmp_path = "/tmp/vmp_edge.conf"
        with sftp.file(tmp_path, "w") as remote_file:
            remote_file.write(config_text)
        _run_command(ssh, f"sudo mv {tmp_path} {remote_path}")
        _run_command(ssh, f"sudo chown root:root {remote_path}")


def _enable_services(ssh: paramiko.SSHClient) -> None:
    _run_command(ssh, "sudo systemctl enable nginx")
    _run_command(ssh, "sudo systemctl restart nginx")


class CDNDeployer:
    def __init__(self, remote_config_path: str = EDGE_CONFIG_REMOTE_PATH) -> None:
        self.remote_config_path = remote_config_path

    def deploy(self, target: DeploymentTarget, config: DeploymentConfig) -> None:
        config.normalize()
        config_text = generate_nginx_config(config)
        ssh = _connect(target)
        try:
            _install_packages(ssh, config.extra_packages)
            firewall_ports = set(config.firewall_ports)
            firewall_ports.add(config.listen_port)
            _configure_firewall(ssh, sorted(firewall_ports))
            _upload_config(ssh, config_text, self.remote_config_path)
            _enable_services(ssh)
        finally:
            ssh.close()


__all__ = [
    "CDNDeployer",
    "DeploymentConfig",
    "DeploymentError",
    "DeploymentTarget",
    "EDGE_CONFIG_REMOTE_PATH",
    "generate_nginx_config",
]
