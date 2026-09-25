"""Alert-type catalog shared by the demo generator and the pipeline.

Each alert type has a default source, title, severity, a behavior family (used for correlation
behavior-compatibility) and an optional kill-chain stage (used by attack-chain construction).
Stages are deliberately assigned only to security-relevant behaviors; routine events have none.
"""

from __future__ import annotations

from dataclasses import dataclass

# Canonical kill-chain stages, in expected order.
STAGES: list[tuple[str, str]] = [
    ("initial_access", "Initial Access"),
    ("credential_attack", "Credential Attack"),
    ("valid_access", "Valid Account / Access"),
    ("execution", "Execution"),
    ("privilege_persistence", "Privilege / Persistence"),
    ("credential_theft", "Credential Theft"),
    ("discovery", "Discovery"),
    ("lateral_movement", "Lateral Movement"),
    ("resource_access", "Sensitive Resource Access"),
    ("exfiltration", "Exfiltration"),
]
STAGE_ORDER = {s: i for i, (s, _) in enumerate(STAGES)}
STAGE_LABEL = dict(STAGES)


@dataclass(frozen=True)
class AlertType:
    source: str
    title: str
    severity: str
    family: str
    stage: str | None = None


ALERT_TYPES: dict[str, AlertType] = {
    # identity
    "login_success": AlertType("identity", "Successful sign-in", "informational", "auth"),
    "failed_login": AlertType("identity", "Failed authentication", "low", "auth_fail", "credential_attack"),
    "account_lockout": AlertType("identity", "Account locked out", "low", "auth_fail", "credential_attack"),
    "password_change": AlertType("identity", "Password changed", "informational", "account"),
    "password_spray_detected": AlertType(
        "identity", "Password spray pattern detected", "high", "auth_fail", "credential_attack"
    ),
    "login_success_after_failures": AlertType(
        "identity", "Successful login after repeated failures", "high", "auth", "valid_access"
    ),
    "login_new_source": AlertType("identity", "Sign-in from new source", "medium", "auth", "valid_access"),
    "new_device_login": AlertType("identity", "Sign-in from unfamiliar device", "medium", "auth", "valid_access"),
    "impossible_travel": AlertType("identity", "Impossible travel sign-in", "high", "auth", "valid_access"),
    "mfa_fatigue": AlertType("identity", "Repeated MFA push requests", "medium", "auth_fail", "credential_attack"),
    "vpn_connection": AlertType("network", "VPN session established", "informational", "auth"),
    "privilege_group_change": AlertType(
        "identity", "User added to privileged group", "high", "privilege", "privilege_persistence"
    ),
    "privileged_role_assigned": AlertType(
        "identity", "Privileged role assigned", "high", "privilege", "privilege_persistence"
    ),
    "account_discovery": AlertType("endpoint", "Account/group enumeration", "medium", "discovery", "discovery"),
    # endpoint
    "powershell_execution": AlertType("endpoint", "PowerShell execution", "medium", "execution", "execution"),
    "encoded_command": AlertType("endpoint", "Encoded PowerShell command", "high", "execution", "execution"),
    "script_execution": AlertType("endpoint", "Script interpreter execution", "medium", "execution", "execution"),
    "suspicious_process": AlertType("endpoint", "Suspicious process behavior", "high", "execution", "execution"),
    "office_spawn_shell": AlertType(
        "endpoint", "Office application spawned a shell", "high", "execution", "execution"
    ),
    "phishing_attachment_opened": AlertType(
        "email", "Suspicious attachment opened", "medium", "email", "initial_access"
    ),
    "admin_script_execution": AlertType(
        "endpoint", "Administrative script execution", "low", "execution", "execution"
    ),
    "scheduled_task_created": AlertType(
        "endpoint", "Scheduled task created", "low", "persistence", "privilege_persistence"
    ),
    "new_service_installed": AlertType(
        "endpoint", "New service installed", "medium", "persistence", "privilege_persistence"
    ),
    "credential_dump": AlertType(
        "endpoint", "Credential dumping behavior (LSASS access)", "critical", "credential_theft", "credential_theft"
    ),
    "remote_service_login": AlertType(
        "network", "Remote desktop logon to server", "medium", "lateral", "lateral_movement"
    ),
    "av_detection_quarantined": AlertType("endpoint", "Potentially unwanted app quarantined", "medium", "malware"),
    "usb_device_connected": AlertType("endpoint", "USB storage device connected", "low", "device"),
    "software_install": AlertType("endpoint", "Software installed", "informational", "system"),
    "service_restart": AlertType("system", "Service restarted", "informational", "system"),
    "patch_installed": AlertType("system", "Patch installed", "informational", "system"),
    "config_change": AlertType("system", "Configuration changed", "low", "system"),
    # network
    "firewall_block": AlertType("network", "Outbound connection blocked", "low", "network"),
    "dns_query_suspicious_tld": AlertType("network", "DNS query to uncommon TLD", "low", "network"),
    "port_scan_internal": AlertType("network", "Internal port scan detected", "medium", "discovery", "discovery"),
    "large_data_transfer": AlertType(
        "network", "Unusually large outbound transfer", "high", "exfil", "exfiltration"
    ),
    # data / cloud
    "file_share_access": AlertType("data", "File share accessed", "informational", "data"),
    "dlp_policy_match": AlertType("data", "DLP policy match", "medium", "data"),
    "email_attachment_blocked": AlertType("email", "Email attachment blocked", "low", "email"),
    "sensitive_resource_access": AlertType(
        "data", "Sensitive resource accessed", "medium", "data_access", "resource_access"
    ),
    "bulk_data_access": AlertType(
        "data", "Unusual volume of records read", "high", "data_access", "resource_access"
    ),
    "mailbox_access": AlertType("cloud", "Mailbox accessed via API", "low", "data_access", "resource_access"),
}

SEVERITY_SCORES = {"informational": 10, "low": 30, "medium": 55, "high": 75, "critical": 92}


def severity_label(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "informational"


# Families that naturally follow each other inside one intrusion ("known sequential behavior").
SEQUENCES: set[tuple[str, str]] = {
    ("auth_fail", "auth"),
    ("auth", "execution"),
    ("auth", "privilege"),
    ("auth", "data_access"),
    ("email", "execution"),
    ("execution", "persistence"),
    ("execution", "privilege"),
    ("execution", "discovery"),
    ("execution", "credential_theft"),
    ("execution", "data_access"),
    ("privilege", "discovery"),
    ("privilege", "data_access"),
    ("privilege", "persistence"),
    ("persistence", "discovery"),
    ("credential_theft", "discovery"),
    ("credential_theft", "lateral"),
    ("discovery", "lateral"),
    ("discovery", "data_access"),
    ("lateral", "data_access"),
    ("lateral", "credential_theft"),
    ("data_access", "exfil"),
    ("lateral", "exfil"),
}
