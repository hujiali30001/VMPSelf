from __future__ import annotations

from typing import List, Optional, Tuple

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

    def fake_run_command(_ssh, command: str, *, sudo_password: Optional[str] = None):
        commands.append(command)
        if "yum -y install" in command:
            install_attempts["count"] += 1
            if install_attempts["count"] == 1:
                raise DeploymentError(
                    "Command failed (1): sudo /usr/bin/yum -y install nginx\nCould not resolve host: mirrorlist.centos.org"
                )
        return ""

    monkeypatch.setattr("app.services.cdn.deployer._run_command", fake_run_command)

    log: List[str] = []
    _install_packages(ssh, ["nginx"], sudo_password=None, log=log)

    assert install_attempts["count"] == 2
    assert any("vault.centos.org" in cmd for cmd in commands)
    assert any("默认仓库不可达" in entry for entry in log)
    assert any("已切换仓库" in entry for entry in log)


def test_install_packages_without_fallback(monkeypatch):
    ssh = _FakeSSH("/usr/bin/yum\n")

    def fake_run_command(_ssh, command: str, *, sudo_password: Optional[str] = None):
        if "yum -y install" in command:
            raise DeploymentError("Command failed (1): sudo yum -y install nginx\nSome other error")
        return ""

    monkeypatch.setattr("app.services.cdn.deployer._run_command", fake_run_command)

    with pytest.raises(DeploymentError):
        _install_packages(ssh, ["nginx"], sudo_password=None, log=[])