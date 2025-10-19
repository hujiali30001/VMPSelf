from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import pytest

from app.services.cdn.deployer import (
    DeploymentConfig,
    DeploymentError,
    _configure_centos_vault_repo,
    _ensure_ssl_assets,
    _install_packages,
    _enable_services,
    _is_tls_enabled,
)


class _FakeStream:
    def __init__(self, payload: str = "") -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload.encode()

    def write(self, _: str) -> None:  # pragma: no cover - stdin placeholder
        return

    def flush(self) -> None:  # pragma: no cover - stdin placeholder
        return


class _FakeSSH:
    def __init__(self, payload: str) -> None:
        self.payload = payload
        self.exec_calls: List[Tuple[str, bool]] = []

    def exec_command(self, command: str, get_pty: bool = False):
        self.exec_calls.append((command, get_pty))
        if "command -v dnf" in command:
            return _FakeStream(), _FakeStream(self.payload), _FakeStream()
        raise AssertionError(f"Unexpected command: {command}")


def test_install_packages_fallback_to_vault(monkeypatch):
    ssh = _FakeSSH("/usr/bin/yum\n")
    commands: List[str] = []
    install_attempts = {"count": 0}
    uploaded: Dict[str, str] = {}

    def fake_run_command(_ssh, command: str, *, sudo_password: Optional[str] = None):
        commands.append(command)
        if "yum -y install" in command:
            install_attempts["count"] += 1
            if install_attempts["count"] == 1:
                raise DeploymentError(
                    "Command failed (1): sudo /usr/bin/yum -y install nginx\nNo package nginx available. Error: Nothing to do"
                )
        if "cat /etc/centos-release" in command:
            return "CentOS Linux release 7.9.2009 (Core)"
        return ""

    monkeypatch.setattr("app.services.cdn.deployer._run_command", fake_run_command)
    monkeypatch.setattr(
        "app.services.cdn.deployer._upload_config",
        lambda _ssh, text, path, *, sudo_password=None: uploaded.update({"path": path, "text": text}),
    )

    log: List[str] = []
    _install_packages(ssh, ["nginx"], sudo_password=None, log=log)

    assert install_attempts["count"] == 2
    assert any("默认仓库不可达" in entry for entry in log)
    assert any("已切换仓库" in entry for entry in log)
    assert uploaded.get("path") == "/etc/yum.repos.d/CentOS-Vault.repo"
    text = uploaded.get("text", "")
    assert "vault.centos.org/7.9.2009/os" in text
    assert "nginx.org/packages/centos/7" in text


def test_install_packages_without_fallback(monkeypatch):
    ssh = _FakeSSH("/usr/bin/yum\n")
    uploaded: Dict[str, str] = {}

    def fake_run_command(_ssh, command: str, *, sudo_password: Optional[str] = None):
        if "yum -y install" in command:
            raise DeploymentError("Command failed (1): sudo yum -y install nginx\nSome other error")
        return ""

    monkeypatch.setattr("app.services.cdn.deployer._run_command", fake_run_command)
    monkeypatch.setattr(
        "app.services.cdn.deployer._upload_config",
        lambda *_args, **_kwargs: uploaded.update({"called": "yes"}),
    )

    with pytest.raises(DeploymentError):
        _install_packages(ssh, ["nginx"], sudo_password=None, log=[])
    assert "called" not in uploaded


def test_install_packages_fallback_for_mirrorlist(monkeypatch):
    ssh = _FakeSSH("/usr/bin/yum\n")
    install_attempts = {"count": 0}

    def fake_run_command(_ssh, command: str, *, sudo_password: Optional[str] = None):
        if "yum -y install" in command:
            install_attempts["count"] += 1
            if install_attempts["count"] == 1:
                raise DeploymentError(
                    "Command failed (1): sudo /usr/bin/yum -y install nginx\nCould not resolve host: mirrorlist.centos.org"
                )
        return ""

    monkeypatch.setattr("app.services.cdn.deployer._run_command", fake_run_command)
    monkeypatch.setattr(
        "app.services.cdn.deployer._configure_centos_vault_repo",
        lambda *_args, **_kwargs: None,
    )

    _install_packages(ssh, ["nginx"], sudo_password=None, log=[])
    assert install_attempts["count"] == 2


def test_configure_vault_repo_skips_missing_repo_files(monkeypatch):
    ssh = object()
    commands: List[str] = []

    def fake_run_command(_ssh, command: str, *, sudo_password: Optional[str] = None):
        commands.append(command)
        if "cat /etc/centos-release" in command:
            return "CentOS Linux release 7.9.2009 (Core)"
        if "CentOS-Updates.repo" in command:
            raise DeploymentError(
                "Command failed (2): sudo sed -i 's/^enabled=1/enabled=0/g' /etc/yum.repos.d/CentOS-Updates.repo\nsed: can't read /etc/yum.repos.d/CentOS-Updates.repo: No such file or directory"
            )
        return ""

    uploaded: Dict[str, str] = {}

    monkeypatch.setattr("app.services.cdn.deployer._run_command", fake_run_command)
    monkeypatch.setattr(
        "app.services.cdn.deployer._upload_config",
        lambda _ssh, text, path, *, sudo_password=None: uploaded.update({"path": path, "text": text}),
    )

    _configure_centos_vault_repo(ssh, sudo_password=None)

    assert uploaded["path"] == "/etc/yum.repos.d/CentOS-Vault.repo"
    assert any("CentOS-Updates.repo" in command for command in commands)
    assert any("yum makecache" in command for command in commands)


def test_ensure_ssl_assets_generates_missing_cert(monkeypatch):
    commands: List[str] = []

    def fake_run_command(_ssh, command: str, *, sudo_password: Optional[str] = None):
        commands.append(command)
        if "test -f" in command:
            raise DeploymentError(f"Command failed (1): {command}\nmissing file")
        return ""

    monkeypatch.setattr("app.services.cdn.deployer._run_command", fake_run_command)

    log: List[str] = []
    _ensure_ssl_assets(
        object(),
        cert_path="/etc/pki/tls/certs/edge.crt",
        key_path="/etc/pki/tls/private/edge.key",
        log=log,
    )

    assert any("openssl req" in command for command in commands)
    assert any("检测到缺少证书文件" in entry for entry in log)
    assert any("已生成自签名证书" in entry for entry in log)


def test_ensure_ssl_assets_custom_path_missing_raises(monkeypatch):
    def fake_run_command(_ssh, command: str, *, sudo_password: Optional[str] = None):
        if "test -f" in command:
            raise DeploymentError(f"Command failed (1): {command}\nmissing file")
        return ""

    monkeypatch.setattr("app.services.cdn.deployer._run_command", fake_run_command)

    with pytest.raises(DeploymentError) as excinfo:
        _ensure_ssl_assets(
            object(),
            cert_path="/custom/cert.pem",
            key_path="/custom/key.pem",
            generate_missing=False,
        )

    assert "/custom/cert.pem" in str(excinfo.value)


def test_is_tls_enabled_false_for_plain_http():
    config = DeploymentConfig(origin_host="edge.local", listen_port=80)

    assert not _is_tls_enabled(config)


def test_is_tls_enabled_true_with_custom_cert_on_port_80():
    config = DeploymentConfig(
        origin_host="edge.local",
        listen_port=80,
        ssl_certificate="/etc/pki/tls/certs/custom.crt",
    )

    assert _is_tls_enabled(config)


def test_enable_services_runs_nginx_test(monkeypatch):
    commands: List[str] = []

    def fake_run_command(_ssh, command: str, *, sudo_password: Optional[str] = None):
        commands.append(command)
        return ""

    monkeypatch.setattr("app.services.cdn.deployer._run_command", fake_run_command)

    _enable_services(object(), sudo_password=None)

    assert commands[0] == "sudo systemctl enable nginx"
    assert "sudo nginx -t" in commands[1]
    assert "sudo systemctl restart nginx" in commands[2]


def test_enable_services_reports_status_on_failure(monkeypatch):
    commands: List[str] = []

    def fake_run_command(_ssh, command: str, *, sudo_password: Optional[str] = None):
        commands.append(command)
        if "systemctl restart" in command:
            raise DeploymentError("Command failed (1): sudo systemctl restart nginx\nerror detail")
        if "status nginx" in command:
            return "Loaded: failed"
        return ""

    monkeypatch.setattr("app.services.cdn.deployer._run_command", fake_run_command)

    with pytest.raises(DeploymentError) as excinfo:
        _enable_services(object(), sudo_password=None)

    assert "Loaded: failed" in str(excinfo.value)
    assert any("status nginx" in cmd for cmd in commands)