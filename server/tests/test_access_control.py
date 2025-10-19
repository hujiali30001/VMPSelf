from __future__ import annotations

from app.core.ip_access import evaluate_ip_access
from app.core.settings import get_settings
from app.db import AccessRuleType, AccessScope
from app.db.session import SessionLocal
from app.services.access_control import AccessControlService


def test_evaluate_ip_access_with_whitelist_requires_ip():
    allowed, reason = evaluate_ip_access(None, ["192.0.2.10"])  # RFC 5737 example IP
    assert allowed is False
    assert reason == "ip_missing"


def test_evaluate_ip_access_blocks_blacklist():
    allowed, reason = evaluate_ip_access("198.51.100.5", blacklist_entries=["198.51.100.0/24"])
    assert allowed is False
    assert reason == "blacklist"



def test_access_control_service_crud_flow(reset_database):
    settings = get_settings()
    with SessionLocal() as session:
        service = AccessControlService(session)
        rule = service.create_rule(scope=AccessScope.CORE, rule_type=AccessRuleType.WHITELIST, value="10.0.0.0/24")
        assert rule.value == "10.0.0.0/24"
        assert settings.core_ip_whitelist == ["10.0.0.0/24"]

        updated = service.update_rule(rule.id, value="10.0.1.0/24", description="office", enabled=True)
        assert updated.value == "10.0.1.0/24"
        assert settings.core_ip_whitelist == ["10.0.1.0/24"]

        service.delete_rule(rule.id)
        assert settings.core_ip_whitelist == []


def test_bulk_replace_updates_settings(reset_database):
    settings = get_settings()
    with SessionLocal() as session:
        service = AccessControlService(session)
        service.bulk_replace(
            scope=AccessScope.CDN,
            rule_type=AccessRuleType.WHITELIST,
            values=["203.0.113.0/28", "203.0.113.10"],
        )
        assert sorted(settings.cdn_ip_manual_whitelist) == ["203.0.113.0/28", "203.0.113.10"]

        service.bulk_replace(
            scope=AccessScope.CDN,
            rule_type=AccessRuleType.BLACKLIST,
            values=["198.51.100.128/25"],
        )
    assert settings.cdn_ip_blacklist == ["198.51.100.128/25"]