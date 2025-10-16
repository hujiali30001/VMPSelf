#!/usr/bin/env python
"""CentOS CDN edge deployment helper.

This script connects to one or more edge servers over SSH, installs
Nginx, and configures it to proxy requests to the origin authorization
service while injecting the shared CDN token header.

Usage:
    python deploy_cdn.py --config cdn_deploy_config.json

The configuration file format is documented in
`cdn_deploy_config.example.json`.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from dataclasses import dataclass, field
from typing import Iterable, Optional

import paramiko

DEFAULT_CONFIG_PATH = pathlib.Path("cdn_deploy_config.json")
EDGE_CONFIG_REMOTE_PATH = "/etc/nginx/conf.d/vmp_edge.conf"
DEFAULT_SSL_CERT = "/etc/pki/tls/certs/edge.crt"
DEFAULT_SSL_KEY = "/etc/pki/tls/private/edge.key"


@dataclass
class HostConfig:
    name: str
    host: str
    user: str
    port: int = 22
    password: Optional[str] = None
    private_key: Optional[str] = None


@dataclass
class DeployConfig:
    origin_host: str
    origin_port: int = 443
    edge_token: str = ""
    ssl_certificate: Optional[str] = None
    ssl_certificate_key: Optional[str] = None
    allow_http: bool = False
    hosts: list[HostConfig] = field(default_factory=list)
    extra_packages: list[str] = field(default_factory=lambda: ["nginx"])
    firewall_ports: list[int] = field(default_factory=lambda: [80, 443])

    @classmethod
    def from_dict(cls, data: dict) -> "DeployConfig":
        hosts = [HostConfig(**item) for item in data.get("hosts", [])]
        return cls(
            origin_host=data["origin_host"],
            origin_port=data.get("origin_port", 443),
            edge_token=data.get("edge_token", ""),
            ssl_certificate=data.get("ssl_certificate"),
            ssl_certificate_key=data.get("ssl_certificate_key"),
            allow_http=data.get("allow_http", False),
            hosts=hosts,
            extra_packages=data.get("extra_packages", ["nginx"]),
            firewall_ports=data.get("firewall_ports", [80, 443]),
        )


def load_config(config_path: pathlib.Path) -> DeployConfig:
    with config_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return DeployConfig.from_dict(data)


def generate_nginx_config(config: DeployConfig) -> str:
    listen_blocks = []
    if config.allow_http:
        listen_blocks.append("    listen 80;")
    ssl_cert = config.ssl_certificate or DEFAULT_SSL_CERT
    ssl_key = config.ssl_certificate_key or DEFAULT_SSL_KEY
    listen_blocks.extend(
        [
            "    listen 443 ssl http2;",
            f"    ssl_certificate {ssl_cert};",
            f"    ssl_certificate_key {ssl_key};",
            "    ssl_protocols TLSv1.2 TLSv1.3;",
            "    ssl_ciphers HIGH:!aNULL:!MD5;",
        ]
    )

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
        "        proxy_set_header Host {host};".format(host=config.origin_host),
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
        f"        proxy_set_header X-Edge-Token \"{config.edge_token}\";",
        "        proxy_cache vmp_cache;",
        "        proxy_cache_valid 200 302 10m;",
        "        proxy_cache_valid 404 1m;",
        "        add_header X-Cache-Status $upstream_cache_status always;",
        "    }",
        "}",
    ]
    return "\n".join(config_block) + "\n"


def connect(host: HostConfig) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=host.host,
        port=host.port,
        username=host.user,
        password=host.password,
        key_filename=host.private_key,
        timeout=20,
    )
    return ssh


def run_command(ssh: paramiko.SSHClient, command: str) -> None:
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        error_output = stderr.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Command failed ({exit_status}): {command}\n{error_output}")


def install_packages(ssh: paramiko.SSHClient, packages: Iterable[str]) -> None:
    pkg_list = " ".join(packages)
    # Determine package manager
    stdin, stdout, _ = ssh.exec_command("command -v dnf || command -v yum")
    manager = stdout.read().decode().strip()
    if not manager:
        raise RuntimeError("Unable to locate dnf or yum on target host")
    run_command(ssh, f"sudo {manager} -y install {pkg_list}")


def configure_firewall(ssh: paramiko.SSHClient, ports: Iterable[int]) -> None:
    stdin, stdout, _ = ssh.exec_command("command -v firewall-cmd")
    if stdout.read().strip():
        for port in ports:
            run_command(ssh, f"sudo firewall-cmd --permanent --add-port={port}/tcp")
        run_command(ssh, "sudo firewall-cmd --reload")


def upload_config(ssh: paramiko.SSHClient, config_text: str, remote_path: str) -> None:
    with ssh.open_sftp() as sftp:
        tmp_path = f"/tmp/vmp_edge.conf"
        with sftp.file(tmp_path, "w") as remote_file:
            remote_file.write(config_text)
        run_command(ssh, f"sudo mv {tmp_path} {remote_path}")
        run_command(ssh, f"sudo chown root:root {remote_path}")


def enable_services(ssh: paramiko.SSHClient) -> None:
    run_command(ssh, "sudo systemctl enable nginx")
    run_command(ssh, "sudo systemctl restart nginx")


def deploy_to_host(host: HostConfig, config: DeployConfig) -> None:
    print(f"[+] Deploying to {host.name} ({host.host})")
    ssh = connect(host)
    try:
        install_packages(ssh, config.extra_packages)
        configure_firewall(ssh, config.firewall_ports)
        nginx_conf = generate_nginx_config(config)
        upload_config(ssh, nginx_conf, EDGE_CONFIG_REMOTE_PATH)
        enable_services(ssh)
        print(f"[✓] Deployment succeeded on {host.name}")
    finally:
        ssh.close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy CDN edge configuration to CentOS hosts")
    parser.add_argument(
        "--config",
        type=pathlib.Path,
        default=DEFAULT_CONFIG_PATH,
        help="Path to deployment configuration JSON",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    config = load_config(args.config)
    if not config.edge_token:
        print("[!] edge_token is empty in configuration", file=sys.stderr)
        return 1

    if args.dry_run:
        print(generate_nginx_config(config))
        return 0

    for host in config.hosts:
        try:
            deploy_to_host(host, config)
        except Exception as exc:  # pylint: disable=broad-except
            print(f"[x] Deployment failed on {host.name}: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
