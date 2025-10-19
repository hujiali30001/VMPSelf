from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import pytest

from app.services.cdn.deployer import (
    DeploymentError,
    _install_packages,
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
                    "Command failed (1): sudo /usr/bin/yum -y install nginx\nCould not resolve host: mirrorlist.centos.org"
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
    assert "vault.centos.org/7.9.2009/os" in uploaded.get("text", "")


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