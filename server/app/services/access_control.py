from __future__ import annotations

import ipaddress
import logging
from typing import Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.settings import get_settings
from app.db import AccessRule, AccessRuleType, AccessScope

logger = logging.getLogger("access_control")


class AccessControlService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def _coerce_scope(self, scope: AccessScope | str) -> AccessScope:
        try:
            return scope if isinstance(scope, AccessScope) else AccessScope(scope)
        except ValueError as exc:
            raise ValueError("scope_invalid") from exc

    def _coerce_rule_type(self, rule_type: AccessRuleType | str) -> AccessRuleType:
        try:
            return rule_type if isinstance(rule_type, AccessRuleType) else AccessRuleType(rule_type)
        except ValueError as exc:
            raise ValueError("rule_type_invalid") from exc

    def _normalize_value(self, value: str) -> str:
        raw = (value or "").strip()
        if not raw:
            raise ValueError("value_required")
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError("value_invalid") from exc

        if network.prefixlen == network.max_prefixlen:
            return network.network_address.compressed
        return network.with_prefixlen

    def list_rules(
        self,
        scope: AccessScope | str,
        *,
        rule_type: Optional[AccessRuleType | str] = None,
        enabled_only: bool = False,
    ) -> List[AccessRule]:
        scope_value = self._coerce_scope(scope).value
        stmt = select(AccessRule).where(AccessRule.scope == scope_value)
        if rule_type is not None:
            stmt = stmt.where(AccessRule.rule_type == self._coerce_rule_type(rule_type).value)
        if enabled_only:
            stmt = stmt.where(AccessRule.enabled.is_(True))
        stmt = stmt.order_by(AccessRule.value.asc())
        return list(self.db.scalars(stmt).all())

    def list_values(
        self,
        scope: AccessScope | str,
        rule_type: AccessRuleType | str,
        *,
        enabled_only: bool = True,
    ) -> List[str]:
        scope_value = self._coerce_scope(scope).value
        stmt = select(AccessRule.value).where(
            AccessRule.scope == scope_value,
            AccessRule.rule_type == self._coerce_rule_type(rule_type).value,
        )
        if enabled_only:
            stmt = stmt.where(AccessRule.enabled.is_(True))
        stmt = stmt.order_by(AccessRule.value.asc())
        return list(self.db.scalars(stmt).all())

    def refresh_settings(self, scope: Optional[AccessScope | str] = None) -> None:
        scopes = [self._coerce_scope(scope)] if scope else [AccessScope.CDN, AccessScope.CORE]
        settings = get_settings()
        for item in scopes:
            whitelist = self.list_values(item, AccessRuleType.WHITELIST)
            blacklist = self.list_values(item, AccessRuleType.BLACKLIST)
            if item == AccessScope.CDN:
                settings.cdn_ip_manual_whitelist = whitelist
                settings.cdn_ip_blacklist = blacklist
            else:
                settings.core_ip_whitelist = whitelist
                settings.core_ip_blacklist = blacklist

    def create_rule(
        self,
        *,
        scope: AccessScope | str,
        rule_type: AccessRuleType | str,
        value: str,
        description: Optional[str] = None,
        enabled: bool = True,
    ) -> AccessRule:
        scope_obj = self._coerce_scope(scope)
        type_obj = self._coerce_rule_type(rule_type)
        normalized_value = self._normalize_value(value)

        existing = self.db.scalar(
            select(AccessRule).where(
                AccessRule.scope == scope_obj.value,
                AccessRule.rule_type == type_obj.value,
                AccessRule.value == normalized_value,
            )
        )
        if existing:
            raise ValueError("rule_exists")

        rule = AccessRule(
            scope=scope_obj.value,
            rule_type=type_obj.value,
            value=normalized_value,
            description=(description or "").strip() or None,
            enabled=bool(enabled),
        )
        self.db.add(rule)
        self.db.commit()
        self.db.refresh(rule)
        self.refresh_settings(scope_obj)
        logger.info(
            "Created access rule",
            extra={
                "scope": scope_obj.value,
                "rule_type": type_obj.value,
                "value": normalized_value,
            },
        )
        return rule

    def update_rule(
        self,
        rule_id: int,
        *,
        value: Optional[str] = None,
        description: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> AccessRule:
        rule = self.db.get(AccessRule, rule_id)
        if not rule:
            raise ValueError("rule_not_found")

        scope_obj = AccessScope(rule.scope)
        changed = False

        if value is not None:
            normalized_value = self._normalize_value(value)
            if normalized_value != rule.value:
                duplicate = self.db.scalar(
                    select(AccessRule).where(
                        AccessRule.id != rule.id,
                        AccessRule.scope == rule.scope,
                        AccessRule.rule_type == rule.rule_type,
                        AccessRule.value == normalized_value,
                    )
                )
                if duplicate:
                    raise ValueError("rule_exists")
                rule.value = normalized_value
                changed = True

        if description is not None:
            rule.description = description.strip() or None
            changed = True

        if enabled is not None and bool(enabled) != rule.enabled:
            rule.enabled = bool(enabled)
            changed = True

        if not changed:
            return rule

        self.db.commit()
        self.db.refresh(rule)
        self.refresh_settings(scope_obj)
        logger.info(
            "Updated access rule",
            extra={
                "id": rule.id,
                "scope": rule.scope,
                "rule_type": rule.rule_type,
            },
        )
        return rule

    def delete_rule(self, rule_id: int) -> None:
        rule = self.db.get(AccessRule, rule_id)
        if not rule:
            raise ValueError("rule_not_found")
        scope_obj = AccessScope(rule.scope)
        self.db.delete(rule)
        self.db.commit()
        self.refresh_settings(scope_obj)
        logger.info(
            "Deleted access rule",
            extra={
                "id": rule_id,
                "scope": scope_obj.value,
                "rule_type": rule.rule_type,
            },
        )

    def bulk_replace(
        self,
        *,
        scope: AccessScope | str,
        rule_type: AccessRuleType | str,
        values: Iterable[str],
    ) -> List[AccessRule]:
        scope_obj = self._coerce_scope(scope)
        type_obj = self._coerce_rule_type(rule_type)
        normalized_values = {self._normalize_value(value) for value in values}

        existing_rules = self.db.scalars(
            select(AccessRule).where(
                AccessRule.scope == scope_obj.value,
                AccessRule.rule_type == type_obj.value,
            )
        ).all()

        existing_map = {rule.value: rule for rule in existing_rules}
        to_keep = set()

        for value in normalized_values:
            if value in existing_map:
                rule = existing_map[value]
                if not rule.enabled:
                    rule.enabled = True
                to_keep.add(rule.id)
            else:
                rule = AccessRule(
                    scope=scope_obj.value,
                    rule_type=type_obj.value,
                    value=value,
                    enabled=True,
                )
                self.db.add(rule)
                self.db.flush()
                to_keep.add(rule.id)

        for rule in existing_rules:
            if rule.id not in to_keep:
                self.db.delete(rule)

        self.db.commit()
        self.refresh_settings(scope_obj)

        return list(
            self.db.scalars(
                select(AccessRule).where(
                    AccessRule.scope == scope_obj.value,
                    AccessRule.rule_type == type_obj.value,
                ).order_by(AccessRule.value.asc())
            ).all()
        )
