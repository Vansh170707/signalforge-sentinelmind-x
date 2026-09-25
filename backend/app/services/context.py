"""Entity context store: identity directory + asset inventory (CMDB analogue) used for enrichment."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ContextStore:
    users: dict[str, dict[str, Any]] = field(default_factory=dict)
    hosts: dict[str, dict[str, Any]] = field(default_factory=dict)
    resources: dict[str, dict[str, Any]] = field(default_factory=dict)
    ip_to_host: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContextStore:
        users = {k.lower(): v for k, v in data.get("users", {}).items()}
        hosts = {k.upper(): v for k, v in data.get("hosts", {}).items()}
        resources = {k.lower(): v for k, v in data.get("resources", {}).items()}
        ip_to_host = {v["ip"]: k for k, v in hosts.items() if v.get("ip")}
        return cls(users=users, hosts=hosts, resources=resources, ip_to_host=ip_to_host)

    @classmethod
    def load(cls, path: Path) -> ContextStore:
        if not path.exists():
            return cls()
        return cls.from_dict(json.loads(path.read_text()))

    def user(self, key: str | None) -> dict[str, Any] | None:
        return self.users.get(key) if key else None

    def host(self, key: str | None) -> dict[str, Any] | None:
        return self.hosts.get(key) if key else None

    def resource(self, key: str | None) -> dict[str, Any] | None:
        if not key:
            return None
        return self.resources.get(key)
