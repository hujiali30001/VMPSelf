from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from typing import Iterable, Optional, Sequence, Tuple, Union

logger = logging.getLogger("access_control")

NetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def _normalize_entries(entries: Optional[Iterable[str]]) -> Tuple[str, ...]:
    normalized = []
    if not entries:
        return tuple()
    for raw in entries:
        if raw is None:
            continue
        value = str(raw).strip()
        if not value:
            continue
        normalized.append(value)
    if not normalized:
        return tuple()
    return tuple(sorted(set(normalized)))


@lru_cache(maxsize=256)
def _compile_networks(entries: Tuple[str, ...]) -> Tuple[NetworkType, ...]:
    compiled: list[NetworkType] = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            logger.warning("Skipping invalid IP rule entry", extra={"entry": entry})
            continue
        compiled.append(network)
    return tuple(compiled)


def evaluate_ip_access(
    ip_value: Optional[str],
    whitelist_entries: Optional[Iterable[str]] = None,
    blacklist_entries: Optional[Iterable[str]] = None,
) -> Tuple[bool, Optional[str]]:
    """Evaluate whether a client IP is allowed by the provided access rules.

    Returns a tuple of (allowed, reason). When access is denied, ``reason`` is one of
    ``"ip_missing"``, ``"ip_invalid"``, ``"blacklist"``, or ``"whitelist"``.
    """

    whitelist_key = _normalize_entries(whitelist_entries)
    blacklist_key = _normalize_entries(blacklist_entries)

    if not ip_value:
        if whitelist_key or blacklist_key:
            return False, "ip_missing"
        return True, None

    candidate = ip_value.strip()
    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        logger.warning("Invalid client IP encountered during access evaluation", extra={"ip": ip_value})
        return False, "ip_invalid"

    if blacklist_key:
        blacklist_networks = _compile_networks(blacklist_key)
        for network in blacklist_networks:
            if ip_obj in network:
                return False, "blacklist"

    if whitelist_key:
        whitelist_networks = _compile_networks(whitelist_key)
        for network in whitelist_networks:
            if ip_obj in network:
                return True, None
        return False, "whitelist"

    return True, None


def merge_entries(*sources: Optional[Sequence[str]]) -> Tuple[str, ...]:
    """Merge multiple iterables of IP/CIDR strings into a normalized tuple."""
    combined: list[str] = []
    for source in sources:
        if not source:
            continue
        combined.extend(source)
    return _normalize_entries(combined)
