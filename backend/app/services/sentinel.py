"""Microsoft Sentinel connector (file-based, advisory).

Import: rows of the Sentinel `SecurityAlert` table as exported from a KQL query (JSON or CSV). `Entities`,
`ExtendedProperties` and `Techniques` may be JSON strings, as Log Analytics returns them. Each row becomes
a raw SentinelMind alert that then goes through normal validation and normalization.

Export: an incident shaped like the body of the Sentinel incidents REST API
(Microsoft.SecurityInsights/incidents) plus related alert IDs, entities and a comment carrying the brief.
SentinelMind never calls Sentinel itself: an analyst or a Logic App decides whether to push it.
"""

from __future__ import annotations

import json
import re
from typing import Any

SENTINEL_KEYS = {"SystemAlertId", "AlertName", "AlertSeverity"}

# First matching rule wins: (all keywords must appear in "AlertName AlertType Description", alert_type)
TYPE_RULES: list[tuple[tuple[str, ...], str]] = [
    (("password spray",), "password_spray_detected"),
    (("impossible travel",), "impossible_travel"),
    (("atypical travel",), "impossible_travel"),
    (("mfa",), "mfa_fatigue"),
    (("locked",), "account_lockout"),
    (("successful", "after", "fail"), "login_success_after_failures"),
    (("brute force",), "brute_force_detected"),
    (("failed", "sign"), "failed_login"),
    (("failed", "logon"), "failed_login"),
    (("unfamiliar sign-in",), "new_device_login"),
    (("new device",), "new_device_login"),
    (("anonymous ip",), "login_new_source"),
    (("unusual location",), "login_new_source"),
    (("new country",), "login_new_source"),
    (("lsass",), "credential_dump"),
    (("credential dump",), "credential_dump"),
    (("mimikatz",), "credential_dump"),
    (("encoded",), "encoded_command"),
    (("office", "child process"), "office_spawn_shell"),
    (("office", "spawn"), "office_spawn_shell"),
    (("powershell",), "powershell_execution"),
    (("certutil",), "suspicious_process"),
    (("script",), "script_execution"),
    (("phish",), "phishing_attachment_opened"),
    (("added to", "group"), "privilege_group_change"),
    (("privileged group",), "privilege_group_change"),
    (("role", "assign"), "privileged_role_assigned"),
    (("scheduled task",), "scheduled_task_created"),
    (("service", "install"), "new_service_installed"),
    (("new service",), "new_service_installed"),
    (("enumeration",), "account_discovery"),
    (("reconnaissance",), "account_discovery"),
    (("port scan",), "port_scan_internal"),
    (("remote desktop",), "remote_service_login"),
    (("rdp",), "remote_service_login"),
    (("lateral",), "remote_service_login"),
    (("exfiltration",), "large_data_transfer"),
    (("unusual volume", "upload"), "large_data_transfer"),
    (("mass download",), "bulk_data_access"),
    (("unusual volume",), "bulk_data_access"),
    (("sensitive", "access"), "sensitive_resource_access"),
    (("mail items accessed",), "mailbox_access"),
    (("mailbox",), "mailbox_access"),
    (("sign-in activity",), "login_success"),
]

PRODUCT_SOURCE = [
    ("identity", "identity"), ("entra", "identity"), ("azure active directory", "identity"),
    ("endpoint", "endpoint"), ("defender for servers", "endpoint"), ("cloud apps", "cloud"),
    ("office 365", "email"), ("defender for office", "email"), ("firewall", "network"), ("network", "network"),
]
SEVERITY_IN = {"high": "high", "medium": "medium", "low": "low", "informational": "informational"}
SEVERITY_OUT = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low"}
TACTIC_NAMES = {
    "credential-access": "CredentialAccess", "initial-access": "InitialAccess", "execution": "Execution",
    "persistence": "Persistence", "privilege-escalation": "PrivilegeEscalation", "stealth": "DefenseEvasion",
    "defense-evasion": "DefenseEvasion", "discovery": "Discovery", "lateral-movement": "LateralMovement",
    "collection": "Collection", "exfiltration": "Exfiltration", "command-and-control": "CommandAndControl",
    "impact": "Impact",
}


def is_sentinel_row(row: dict[str, Any]) -> bool:
    return len(SENTINEL_KEYS & set(row)) >= 2


def _json(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value


def classify(name: str, alert_type: str, description: str) -> str:
    from app.services.catalog import ALERT_TYPES

    if alert_type in ALERT_TYPES:  # connector-native type id (analytics rule name or our own exports)
        return alert_type
    text = f"{name} {alert_type} {description}".lower()
    for keywords, atype in TYPE_RULES:
        if all(k in text for k in keywords):
            return atype
    return "sentinel_alert"


def _source(product: str) -> str:
    p = product.lower()
    return next((src for key, src in PRODUCT_SOURCE if key in p), "sentinel")


def from_sentinel(row: dict[str, Any]) -> dict[str, Any]:
    """Map one SecurityAlert row to a raw SentinelMind alert (normalization validates it afterwards)."""
    entities = _json(row.get("Entities"), [])
    by_id = {e.get("$id"): e for e in entities if isinstance(e, dict)}
    users, hosts, ips, procs, resources = [], [], [], [], []
    for e in entities:
        if not isinstance(e, dict):
            continue
        etype = str(e.get("Type", "")).lower()
        if etype == "account" and e.get("Name"):
            users.append(e["Name"])
        elif etype == "host" and (e.get("HostName") or e.get("NetBiosName")):
            hosts.append(e.get("HostName") or e.get("NetBiosName"))
        elif etype == "ip" and e.get("Address"):
            ips.append(e["Address"])
        elif etype == "process":
            image = e.get("ImageFile")
            if isinstance(image, dict) and "$ref" in image:
                image = by_id.get(image["$ref"], {})
            name = (image or {}).get("Name") if isinstance(image, dict) else None
            procs.append({"name": name, "command_line": e.get("CommandLine")})
        elif etype == "mailbox" and e.get("MailboxPrimaryAddress"):
            resources.append(f"mailbox:{e['MailboxPrimaryAddress'].split('@')[0]}")
        elif etype in ("cloud-application", "azure-resource") and (e.get("Name") or e.get("ResourceId")):
            resources.append(str(e.get("Name") or e.get("ResourceId")).split("/")[-1].lower())

    ext = _json(row.get("ExtendedProperties"), {})
    techniques = _json(row.get("Techniques"), [])
    if isinstance(techniques, str):
        techniques = [t.strip() for t in techniques.split(",") if t.strip()]
    sub = _json(row.get("SubTechniques"), [])
    if isinstance(sub, list):
        techniques = list(techniques) + sub
    name = str(row.get("AlertName") or row.get("DisplayName") or "Sentinel alert")
    atype = classify(name, str(row.get("AlertType") or ""), str(row.get("Description") or ""))
    product = str(row.get("ProductName") or row.get("ProviderName") or "Microsoft Sentinel")
    sev = SEVERITY_IN.get(str(row.get("AlertSeverity", "")).lower())
    proc = next((p for p in procs if p["name"] or p["command_line"]), None)

    attributes: dict[str, Any] = {k: v for k, v in (ext.items() if isinstance(ext, dict) else []) if v is not None}
    if proc and proc["command_line"]:
        attributes.setdefault("command_line", proc["command_line"])
    if techniques:
        attributes["vendor_techniques"] = [t for t in techniques if re.fullmatch(r"T\d{4}(\.\d{3})?", str(t))]
    if row.get("Tactics"):
        attributes["vendor_tactics"] = str(row["Tactics"])
    attributes["sentinel_alert_name"] = name
    if row.get("CompromisedEntity"):
        # Canonical form so the same alert exported twice dedupes (DOMAIN\user, UPN and case variants).
        attributes["compromised_entity"] = str(row["CompromisedEntity"]).split("\\")[-1].split("@")[0].lower()

    confidence = row.get("ConfidenceScore")
    return {
        "alert_id": str(row.get("SystemAlertId") or row.get("VendorOriginalId") or ""),
        "timestamp": row.get("StartTime") or row.get("TimeGenerated"),
        "source": _source(product),
        "vendor": product,
        "alert_type": atype,
        "title": name,
        "severity": sev,
        "confidence": float(confidence) if confidence not in (None, "") else None,
        "user": users[0] if users else None,
        "host": hosts[0] if hosts else None,
        "src_ip": ips[0] if ips else None,
        "dst_ip": ips[1] if len(ips) > 1 else None,
        "process": proc["name"] if proc and proc["name"] else None,
        "resource": resources[0] if resources else None,
        "raw_event_ref": f"sentinel:{row.get('SystemAlertId')}",
        "attributes": attributes,
    }


def convert_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Convert any Sentinel rows in a batch; returns (rows, converted_count). Other rows pass through."""
    out, n = [], 0
    for r in rows:
        if isinstance(r, dict) and is_sentinel_row(r):
            converted = {k: v for k, v in from_sentinel(r).items() if v is not None}
            converted["raw_original"] = r
            out.append(converted)
            n += 1
        else:
            out.append(r)
    return out, n


def _entity(e: dict[str, Any], ctx_host: dict[str, Any] | None = None) -> dict[str, Any] | None:
    t, v = e["type"], e["value"]
    if t == "user":
        return {"kind": "Account", "properties": {"accountName": v, "friendlyName": v}}
    if t == "host":
        return {"kind": "Host", "properties": {"hostName": v, "friendlyName": v}}
    if t == "ip":
        return {"kind": "Ip", "properties": {"address": v, "friendlyName": v}}
    if t == "process":
        return {"kind": "File", "properties": {"fileName": v, "friendlyName": v}}
    if t == "resource":
        return {"kind": "CloudApplication", "properties": {"appName": v, "friendlyName": v}}
    return None


def to_sentinel_incident(view: dict[str, Any], brief: dict[str, Any] | None, alert_ids: list[str],
                         catalog_tactics: dict[str, list[str]]) -> dict[str, Any]:
    tactics = sorted({TACTIC_NAMES.get(t, t) for m in view.get("mitre", []) for t in catalog_tactics.get(
        m["technique_id"], [])})
    techniques = [m["technique_id"] for m in view.get("mitre", [])]
    verdict = view.get("analyst_verdict")
    classification = {"confirmed_malicious": "TruePositive", "false_positive": "FalsePositive",
                      "benign_true_positive": "BenignPositive"}.get(verdict or "")
    status = "Closed" if view.get("status") == "closed" else "Active" if verdict else "New"
    summary = (brief or {}).get("executive_summary") or view["title"]
    facts = (brief or {}).get("observed_facts", [])[:6]
    comment = summary + "\n\nObserved facts:\n" + "\n".join(
        f"- {f['fact']} [{', '.join(f['alert_ids'][:3])}]" for f in facts)
    props: dict[str, Any] = {
        "title": view["title"],
        "description": summary,
        "severity": SEVERITY_OUT.get(view["severity"], "Informational"),
        "status": status,
        "firstActivityTimeUtc": view["first_seen"],
        "lastActivityTimeUtc": view["last_seen"],
        "providerName": "SentinelMind X",
        "providerIncidentId": view["incident_id"],
        "labels": [{"labelName": "SentinelMind X", "labelType": "User"},
                   {"labelName": f"risk:{round(view['risk_score'])}", "labelType": "User"}]
        + [{"labelName": t, "labelType": "User"} for t in techniques[:10]],
        "additionalData": {"alertsCount": view["alert_count"], "tactics": tactics, "techniques": techniques,
                           "alertProductNames": ["SentinelMind X"]},
    }
    if classification:
        props["classification"] = classification
        props["classificationComment"] = "Analyst verdict recorded in SentinelMind X"
    return {
        "apiVersion": "Microsoft.SecurityInsights/incidents (payload shape)",
        "properties": props,
        "relatedAlertIds": alert_ids,
        "entities": [x for x in (_entity(e) for e in view.get("primary_entities", [])) if x],
        "comments": [{"properties": {"message": comment[:30000]}}],
        "riskBreakdown": view.get("risk", {}).get("contributions", {}),
    }


# ---------------------------------------------------------------- demo corpus -> Sentinel export rows
SENTINEL_NAMES: dict[str, str] = {
    "failed_login": "Failed sign-in attempt",
    "account_lockout": "Account locked after failed sign-in attempts",
    "login_success": "Sign-in activity",
    "login_success_after_failures": "Successful sign-in after multiple failed attempts",
    "login_new_source": "Sign-in from an unusual location",
    "new_device_login": "Unfamiliar sign-in properties",
    "impossible_travel": "Impossible travel activity",
    "mfa_fatigue": "MFA push notification fatigue",
    "password_spray_detected": "Password spray attack",
    "powershell_execution": "Suspicious PowerShell command line",
    "encoded_command": "Suspicious encoded PowerShell command",
    "script_execution": "Suspicious script interpreter activity",
    "office_spawn_shell": "Office application spawned a child process",
    "phishing_attachment_opened": "Phish delivered and attachment opened",
    "privilege_group_change": "User added to privileged group",
    "privileged_role_assigned": "Privileged role assigned outside PIM",
    "account_discovery": "Account enumeration reconnaissance",
    "scheduled_task_created": "Suspicious scheduled task created",
    "new_service_installed": "Suspicious service installation",
    "credential_dump": "Credential dump from LSASS memory",
    "remote_service_login": "Remote desktop logon to server",
    "sensitive_resource_access": "Sensitive data access",
    "bulk_data_access": "Unusual volume of records read (mass download)",
    "large_data_transfer": "Possible data exfiltration: unusual volume upload",
    "mailbox_access": "Mail items accessed via API",
    "port_scan_internal": "Internal port scan detected",
}
PRODUCT_BY_SOURCE = {
    "identity": "Microsoft Entra ID Protection", "endpoint": "Microsoft Defender for Endpoint",
    "network": "Microsoft Defender for Endpoint", "data": "Microsoft Defender for Cloud Apps",
    "cloud": "Microsoft Defender for Cloud Apps", "email": "Microsoft Defender for Office 365",
    "system": "Azure Monitor",
}
VENDOR_TECHNIQUES = {
    "failed_login": ["T1110"], "password_spray_detected": ["T1110"], "impossible_travel": ["T1078"],
    "powershell_execution": ["T1059"], "encoded_command": ["T1059", "T1027"], "credential_dump": ["T1003"],
    "privilege_group_change": ["T1098"], "account_discovery": ["T1087"], "large_data_transfer": ["T1048"],
}


def to_sentinel_alert_row(a: dict[str, Any]) -> dict[str, Any]:
    """Render a raw demo alert as a Sentinel SecurityAlert row (KQL JSON export style, JSON-string columns)."""
    if not a.get("alert_type") or a.get("alert_type") not in SENTINEL_NAMES and a.get("alert_type") not in (
            "file_share_access", "vpn_connection", "software_install", "service_restart", "patch_installed",
            "config_change", "firewall_block", "dns_query_suspicious_tld", "usb_device_connected",
            "av_detection_quarantined", "dlp_policy_match", "email_attachment_blocked", "password_change",
            "admin_script_execution"):
        return a  # malformed / unknown rows pass through unchanged so they are still rejected
    atype = a["alert_type"]
    ents: list[dict[str, Any]] = []
    n = 1

    def add(e: dict[str, Any]) -> str:
        nonlocal n
        n += 1
        e["$id"] = str(n)
        ents.append(e)
        return e["$id"]

    user = a.get("user")
    if user:
        name = user.split("\\")[-1].split("@")[0]
        add({"Type": "account", "Name": name, "UPNSuffix": "corp.example"})
    if a.get("host"):
        add({"Type": "host", "HostName": str(a["host"]).split(".")[0], "DnsDomain": "corp.local"})
    for ip in (a.get("src_ip"), a.get("dst_ip")):
        if ip:
            add({"Type": "ip", "Address": ip})
    if a.get("process"):
        fid = add({"Type": "file", "Name": a["process"]})
        add({"Type": "process", "CommandLine": (a.get("attributes") or {}).get("command_line"),
             "ImageFile": {"$ref": fid}})
    if a.get("resource"):
        res = str(a["resource"])
        if res.startswith("mailbox:"):
            add({"Type": "mailbox", "MailboxPrimaryAddress": f"{res.split(':', 1)[1]}@corp.example"})
        else:
            add({"Type": "cloud-application", "Name": res})
    ext = {k: v for k, v in (a.get("attributes") or {}).items() if k != "command_line"}
    title = SENTINEL_NAMES.get(atype) or a.get("title") or atype
    if atype == "suspicious_process":
        cmd = str((a.get("attributes") or {}).get("command_line", "")).lower()
        title = "Credential dump from LSASS memory via rundll32" if "minidump" in cmd else \
            "Suspicious certutil download"
    sev = a.get("severity") or "medium"
    return {
        "TimeGenerated": a["timestamp"], "StartTime": a["timestamp"], "EndTime": a["timestamp"],
        # Named detections go through keyword classification (AlertType blank, like vendor GUID types);
        # routine telemetry keeps its analytics-rule type id.
        "SystemAlertId": a["alert_id"], "AlertName": title, "AlertType": "" if atype in SENTINEL_NAMES else atype,
        "AlertSeverity": {"critical": "High", "informational": "Informational"}.get(sev, sev.capitalize()),
        "Description": title, "ProductName": PRODUCT_BY_SOURCE.get(a.get("source", ""), "Microsoft Sentinel"),
        "ProviderName": "ASI Scheduled Alerts" if a.get("source") == "system" else "MDATP",
        "ConfidenceScore": a.get("confidence"), "CompromisedEntity": user or a.get("host"),
        "Entities": json.dumps(ents), "ExtendedProperties": json.dumps(ext),
        "Techniques": json.dumps(VENDOR_TECHNIQUES.get(atype, [])),
    }
