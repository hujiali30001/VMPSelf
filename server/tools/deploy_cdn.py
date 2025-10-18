#!/usr/bin/env python
"""CentOS CDN edge deployment helper.

This script connects to one or more edge servers over SSH, installs
Nginx, and configures it to proxy requests to the origin authorization
service. It supports both HTTPS反向代理 (HTTP 模式) 和 TCP 四层转发
模式，复用应用服务中的部署逻辑。

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
from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.cdn.deployer import (  # type: ignore  # noqa: E402
    CDNDeployer,
    DeploymentConfig,
    DeploymentError,
    DeploymentTarget,
    generate_nginx_config,
)

DEFAULT_CONFIG_PATH = pathlib.Path("cdn_deploy_config.json")


@dataclass
class HostConfig:
    name: str
    host: str
    user: str
    port: int = 22
    password: Optional[str] = None
    private_key: Optional[str] = None

    def to_deployment_target(self) -> DeploymentTarget:
        return DeploymentTarget(
            name=self.name,
            host=self.host,
            username=self.user,
            port=self.port,
            password=self.password,
            private_key=self.private_key,
        )


@dataclass
class DeployConfig:
    origin_host: str
    origin_port: int = 443
    listen_port: int = 443
    mode: str = "http"
    edge_token: Optional[str] = None
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
            listen_port=data.get("listen_port", data.get("origin_port", 443)),
            mode=data.get("mode", "http"),
            edge_token=data.get("edge_token"),
            ssl_certificate=data.get("ssl_certificate"),
            ssl_certificate_key=data.get("ssl_certificate_key"),
            allow_http=data.get("allow_http", False),
            hosts=hosts,
            extra_packages=data.get("extra_packages", ["nginx"]),
            firewall_ports=data.get("firewall_ports", [80, 443]),
        )

    def to_deployment_config(self) -> DeploymentConfig:
        return DeploymentConfig(
            origin_host=self.origin_host,
            origin_port=self.origin_port,
            listen_port=self.listen_port,
            edge_token=self.edge_token,
            mode=self.mode,
            allow_http=self.allow_http,
            ssl_certificate=self.ssl_certificate,
            ssl_certificate_key=self.ssl_certificate_key,
            extra_packages=self.extra_packages,
            firewall_ports=self.firewall_ports,
        )


def load_config(config_path: pathlib.Path) -> DeployConfig:
    with config_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return DeployConfig.from_dict(data)


def deploy_to_host(host: HostConfig, config: DeployConfig, deployer: CDNDeployer) -> None:
    print(f"[+] Deploying to {host.name} ({host.host})")
    try:
        deployer.deploy(host.to_deployment_target(), config.to_deployment_config())
    except DeploymentError as exc:
        raise RuntimeError(str(exc)) from exc
    print(f"[✓] Deployment succeeded on {host.name}")


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

    if args.dry_run:
        print(generate_nginx_config(config.to_deployment_config()))
        return 0

    deployer = CDNDeployer()
    for host in config.hosts:
        try:
            deploy_to_host(host, config, deployer)
        except Exception as exc:  # pylint: disable=broad-except
            print(f"[x] Deployment failed on {host.name}: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
