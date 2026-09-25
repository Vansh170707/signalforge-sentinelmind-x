"""Local defensive knowledge: synthetic SOC playbook checks keyed by ATT&CK technique / attack stage.

Retrieval is by technique ID + stage (metadata-first, per blueprint 19.1), never free text. Every returned
item is labelled "recommended by playbook" so the brief keeps it separate from observed incident facts.
"""

from __future__ import annotations

PLAYBOOK_BY_TECHNIQUE: dict[str, list[str]] = {
    "T1110": ["Review all authentication attempts for the targeted account in the surrounding 24 hours.",
              "Check whether the source IP appears in other tenants' sign-in logs or threat intel.",
              "Confirm whether the account has MFA enforced for the protocol used."],
    "T1110.003": ["List every account that received attempts from the spraying source and flag successes.",
                  "Force password reset and session revocation for accounts that signed in successfully.",
                  "Check for the same source across VPN, IdP and mail gateways."],
    "T1078": ["Validate the successful sign-in with the account owner out-of-band.",
              "Review the session's subsequent activity, device and token properties.",
              "Revoke active sessions if the owner does not recognize the sign-in."],
    "T1078.004": ["Compare sign-in geography and client app with the user's recent history.",
                  "Review mailbox rules, OAuth grants and forwarding created during the session."],
    "T1059.001": ["Retrieve full PowerShell script-block logs for the host and decode encoded commands.",
                  "Identify the parent process chain for each PowerShell execution."],
    "T1027": ["Decode obfuscated command lines in an isolated analysis environment."],
    "T1105": ["Identify files written by the download command and submit hashes for reputation checks."],
    "T1003.001": ["Treat credentials cached on the host as compromised; plan resets for privileged accounts.",
                  "Check EDR telemetry for LSASS handle access and dump files on disk."],
    "T1098": ["Diff privileged group and role membership against the last approved baseline."],
    "T1098.007": ["Confirm each privileged group change against an approved change ticket."],
    "T1543.003": ["Inspect newly installed services: binary path, signer and creating account."],
    "T1053.005": ["List scheduled tasks created in the window and their actions and triggers."],
    "T1087.002": ["Correlate enumeration commands with the account's normal administrative duties."],
    "T1021.001": ["Map the RDP source-to-destination chain and check whether it is a normal admin path."],
    "T1213": ["Quantify records read from the sensitive repository and compare with the user's baseline.",
              "Notify the data owner if bulk access is confirmed."],
    "T1039": ["List files read from the share and check for staging or archive creation."],
    "T1048": ["Measure outbound volume to the destination and block/contain only after analyst approval."],
    "T1114.002": ["Review which mailbox items were read via API and by which client application."],
    "T1621": ["Ask the user whether they received unexpected MFA prompts; consider number matching."],
    "T1566.001": ["Pull the original email and attachment; search for the same sender/attachment tenant-wide."],
    "T1204.002": ["Detonate the attachment in a sandbox and collect indicators."],
    "T1046": ["Confirm whether the scanning host is an authorised vulnerability scanner."],
}

PLAYBOOK_BY_STAGE: dict[str, list[str]] = {
    "credential_attack": ["Check whether the credential attack preceded any successful authentication."],
    "valid_access": ["Verify the legitimacy of new sources/devices with the account owner."],
    "execution": ["Collect process tree and command lines from the host EDR."],
    "privilege_persistence": ["Review privilege and persistence changes against change management."],
    "resource_access": ["Confirm business justification for sensitive data access with the data owner."],
    "exfiltration": ["Determine data volume and destination ownership before any containment decision."],
}

GENERAL = ["Record the analyst verdict so the feedback loop can tune correlation and risk weights."]


def checks_for(technique_ids: list[str], stages: list[str], limit: int = 6) -> list[str]:
    out: list[str] = []
    for tid in technique_ids:
        for c in PLAYBOOK_BY_TECHNIQUE.get(tid, []):
            if c not in out:
                out.append(c)
    for st in stages:
        for c in PLAYBOOK_BY_STAGE.get(st, []):
            if c not in out:
                out.append(c)
    if not out:
        out = ["Review the grouped alerts for business justification before closing."]
    return (out + GENERAL)[:limit]
