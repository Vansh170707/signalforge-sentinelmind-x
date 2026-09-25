"""MITRE ATT&CK layer (blueprint section 18).

The application owns every mapping. Rules are deterministic and evidence-based; technique IDs and
names are resolved only through the cached official catalog (data/mitre/attack_catalog.json built by
scripts/download_mitre.py from the ATT&CK STIX 2.1 bundle). Unknown IDs are rejected.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.schemas.alerts import CanonicalAlert


class AttackCatalog:
    def __init__(self, data: dict[str, Any]):
        self.version = str(data.get("attack_version", "unknown"))
        self.techniques: dict[str, dict[str, Any]] = data.get("techniques", {})
        self.tactics: dict[str, dict[str, Any]] = data.get("tactics", {})

    @classmethod
    def load(cls, path: Path) -> AttackCatalog:
        return cls(json.loads(path.read_text()))

    def get(self, technique_id: str) -> dict[str, Any] | None:
        return self.techniques.get(technique_id)

    def is_valid(self, technique_id: str) -> bool:
        return technique_id in self.techniques

    def tactic_names(self, technique_id: str) -> list[str]:
        t = self.techniques.get(technique_id) or {}
        return [self.tactics.get(s, {}).get("name", s) for s in t.get("tactics", [])]


@lru_cache
def get_catalog() -> AttackCatalog:
    return AttackCatalog.load(get_settings().mitre_catalog_path)


@dataclass
class Mapping:
    technique_id: str
    name: str
    tactics: list[str]
    confidence: float
    evidence_alert_ids: list[str]
    mapping_reason: str
    attack_catalog_version: str


Rule = Callable[[list[CanonicalAlert]], list[tuple[str, float, list[CanonicalAlert], str]]]


def _of(alerts: list[CanonicalAlert], *types: str) -> list[CanonicalAlert]:
    return [a for a in alerts if a.alert_type in types]


def _span_min(items: list[CanonicalAlert]) -> float:
    ts = [a.timestamp for a in items]
    return (max(ts) - min(ts)).total_seconds() / 60 if ts else 0.0


def _cmd(a: CanonicalAlert) -> str:
    return str(a.attributes.get("command_line", "")).lower()


def rule_brute_force(alerts: list[CanonicalAlert]):
    fails = _of(alerts, "failed_login")
    out = []
    detected = _of(alerts, "brute_force_detected")
    if detected and not _of(alerts, "password_spray_detected"):
        users = sorted({a.user for a in detected if a.user})
        return [("T1110", 0.85, detected + fails,
                 f"{len(detected)} brute-force detections" + (f" for {', '.join(users[:3])}" if users else ""))]
    by_src_users: dict[str, set[str]] = defaultdict(set)
    for a in fails:
        if a.src_ip and a.user:
            by_src_users[a.src_ip].add(a.user)
    spray_detected = _of(alerts, "password_spray_detected")
    spray_src = [s for s, users in by_src_users.items() if len(users) >= 10]
    if spray_src or spray_detected:
        src = spray_src[0] if spray_src else (spray_detected[0].src_ip or "unknown")
        ev = [a for a in fails if a.src_ip == src] + spray_detected
        users = len(by_src_users.get(src, set()))
        out.append(("T1110.003", min(0.97, 0.7 + 0.002 * len(ev)), ev,
                    f"{len(fails)} failed logins across {users} accounts from {src} within "
                    f"{_span_min(ev):.0f} minutes"))
        return out
    per_user = Counter(a.user for a in fails if a.user)
    if per_user:
        user, count = per_user.most_common(1)[0]
        if count >= 10:
            ev = [a for a in fails if a.user == user]
            srcs = Counter(a.src_ip for a in ev if a.src_ip)
            src = f" from {srcs.most_common(1)[0][0]}" if srcs else ""
            out.append(("T1110", min(0.98, 0.7 + 0.004 * count), ev,
                        f"{count} failed logins for {user}{src} within {_span_min(ev):.0f} minutes"))
    return out


def rule_valid_accounts(alerts: list[CanonicalAlert]):
    out = []
    travel = _of(alerts, "impossible_travel")
    if travel:
        out.append(("T1078.004", 0.85, travel + _of(alerts, "login_new_source"),
                    "sign-in from a geographically impossible location for the same cloud account"))
    strong = _of(alerts, "login_success_after_failures", "new_device_login")
    external_new = [a for a in _of(alerts, "login_new_source") if a.src_ip and a.src_ip_private is False
                    and not a.src_ip.startswith("100.")]
    if strong or (external_new and not travel):
        ev = strong + external_new
        conf = 0.9 if _of(alerts, "login_success_after_failures") else 0.65
        out.append(("T1078", conf, ev, "account used successfully after failures / from a new source or device"))
    return out


def rule_execution(alerts: list[CanonicalAlert]):
    out = []
    ps = _of(alerts, "powershell_execution", "encoded_command")
    ps = [a for a in ps if a.process in (None, "powershell.exe", "pwsh.exe") or "powershell" in _cmd(a)]
    if ps:
        out.append(("T1059.001", min(0.95, 0.6 + 0.02 * len(ps)), ps, f"{len(ps)} PowerShell executions"))
    enc = _of(alerts, "encoded_command")
    if enc:
        out.append(("T1027", 0.8, enc, f"{len(enc)} encoded/obfuscated command lines"))
    scripts = _of(alerts, "script_execution")
    if scripts:
        out.append(("T1059", 0.7, scripts, f"{len(scripts)} script interpreter executions"))
    office = _of(alerts, "office_spawn_shell")
    if office:
        out.append(("T1204.002", 0.85, office, "Office application spawned a command shell"))
    phish = _of(alerts, "phishing_attachment_opened")
    if phish:
        out.append(("T1566.001", 0.75, phish, "suspicious attachment opened by the user"))
    dl = [a for a in _of(alerts, "suspicious_process") if "urlcache" in _cmd(a)]
    if dl:
        out.append(("T1105", 0.85, dl, "certutil used to download a remote file"))
    return out


def rule_credential_theft(alerts: list[CanonicalAlert]):
    ev = _of(alerts, "credential_dump") + [a for a in _of(alerts, "suspicious_process")
                                           if "minidump" in _cmd(a) or "lsass" in _cmd(a)]
    return [("T1003.001", 0.9, ev, "process access / dump of LSASS memory")] if ev else []


def rule_privilege(alerts: list[CanonicalAlert]):
    out = []
    grp = _of(alerts, "privilege_group_change")
    if grp:
        out.append(("T1098.007", 0.85, grp, f"{len(grp)} additions to privileged groups"))
    role = _of(alerts, "privileged_role_assigned")
    if role:
        out.append(("T1098", 0.8, role, f"{len(role)} privileged role assignments"))
    svc = _of(alerts, "new_service_installed")
    if svc:
        out.append(("T1543.003", 0.75, svc, f"{len(svc)} new Windows services installed"))
    task = _of(alerts, "scheduled_task_created")
    if task:
        out.append(("T1053.005", 0.7, task, f"{len(task)} scheduled tasks created"))
    return out


def rule_discovery(alerts: list[CanonicalAlert]):
    out = []
    disc = _of(alerts, "account_discovery")
    if disc:
        domain = [a for a in disc if "/domain" in _cmd(a)]
        if domain:
            out.append(("T1087.002", 0.85, domain, "domain account/group enumeration commands"))
        else:
            out.append(("T1087", 0.7, disc, "account enumeration activity"))
    scan = _of(alerts, "port_scan_internal")
    if scan:
        out.append(("T1046", 0.6, scan, f"{len(scan)} internal port-scan detections"))
    return out


def rule_lateral(alerts: list[CanonicalAlert]):
    rdp = _of(alerts, "remote_service_login")
    if not rdp:
        return []
    is_rdp = [a for a in rdp if str(a.attributes.get("logon_type", "")).upper() == "RDP"]
    if is_rdp:
        return [("T1021.001", 0.8, is_rdp, f"{len(is_rdp)} remote desktop logons to servers")]
    return [("T1021", 0.7, rdp, f"{len(rdp)} remote service logons")]


def rule_collection_exfil(alerts: list[CanonicalAlert]):
    out = []
    data = _of(alerts, "sensitive_resource_access", "bulk_data_access")
    shares = [a for a in data if a.attributes.get("share")]
    repos = [a for a in data if not a.attributes.get("share")]
    if repos:
        res = Counter(a.resource for a in repos if a.resource).most_common(1)
        out.append(("T1213", min(0.9, 0.6 + 0.01 * len(repos)), repos,
                    f"{len(repos)} reads of sensitive repository {res[0][0] if res else ''}".strip()))
    if shares:
        out.append(("T1039", 0.8, shares, f"{len(shares)} bulk reads from a network share"))
    mail = _of(alerts, "mailbox_access")
    if len(mail) >= 10:
        out.append(("T1114.002", 0.75, mail, f"{len(mail)} remote mailbox API reads"))
    exfil = _of(alerts, "large_data_transfer")
    if exfil:
        dst = Counter(a.dst_ip for a in exfil if a.dst_ip).most_common(1)
        out.append(("T1048", 0.8, exfil, f"{len(exfil)} unusually large outbound transfers"
                    + (f" to {dst[0][0]}" if dst else "")))
    mfa = _of(alerts, "mfa_fatigue")
    if len(mfa) >= 5:
        out.append(("T1621", 0.85, mfa, f"{len(mfa)} repeated MFA push requests"))
    return out


def rule_vendor_reported(alerts: list[CanonicalAlert]):
    """Techniques reported by the source product (e.g. Microsoft Sentinel `Techniques`). Lower confidence
    than behavior rules; IDs are still validated and named from the local catalog."""
    by_tid: dict[str, list[CanonicalAlert]] = defaultdict(list)
    for a in alerts:
        for tid in a.attributes.get("vendor_techniques", []) or []:
            by_tid[str(tid)].append(a)
    return [(tid, 0.6, ev, f"reported by {ev[0].vendor} on {len(ev)} alert(s)") for tid, ev in by_tid.items()]


RULES: list[Rule] = [rule_brute_force, rule_valid_accounts, rule_execution, rule_credential_theft,
                     rule_privilege, rule_discovery, rule_lateral, rule_collection_exfil, rule_vendor_reported]


def map_incident(alerts: list[CanonicalAlert], catalog: AttackCatalog | None = None) -> list[Mapping]:
    cat = catalog or get_catalog()
    out: dict[str, Mapping] = {}
    for rule in RULES:
        for tid, conf, ev, reason in rule(alerts):
            info = cat.get(tid)
            if info is None or not ev:
                continue  # never emit IDs that are absent from the official catalog
            ev_ids = [a.alert_id for a in sorted(ev, key=lambda a: a.timestamp)]
            if tid in out:
                continue
            out[tid] = Mapping(
                technique_id=tid, name=info["name"], tactics=cat.tactic_names(tid), confidence=round(conf, 3),
                evidence_alert_ids=ev_ids, mapping_reason=reason, attack_catalog_version=cat.version,
            )
    return sorted(out.values(), key=lambda m: -m.confidence)
