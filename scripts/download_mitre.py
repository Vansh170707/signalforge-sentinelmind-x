"""Download the official MITRE ATT&CK Enterprise STIX 2.1 bundle and build a compact local catalog.

The full bundle (~45 MB) is cached at data/mitre/enterprise-attack.json (git-ignored).
The compact catalog (data/mitre/attack_catalog.json) is committed so the app works offline:
it contains every non-revoked, non-deprecated technique with its official ID, name, tactics,
a truncated description and the ATT&CK release version.

Usage:
    python scripts/download_mitre.py            # download + build
    python scripts/download_mitre.py --offline  # rebuild catalog from an existing bundle
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
BUNDLE_PATH = ROOT / "data" / "mitre" / "enterprise-attack.json"
CATALOG_PATH = ROOT / "data" / "mitre" / "attack_catalog.json"


def download() -> None:
    BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {BUNDLE_URL} ...")
    import httpx  # certifi-backed TLS; avoids missing system CA bundles

    resp = httpx.get(BUNDLE_URL, timeout=180, follow_redirects=True)
    resp.raise_for_status()
    BUNDLE_PATH.write_bytes(resp.content)
    print(f"Saved {BUNDLE_PATH} ({BUNDLE_PATH.stat().st_size / 1e6:.1f} MB)")


def build_catalog() -> dict:
    bundle = json.loads(BUNDLE_PATH.read_text())
    objects = bundle["objects"]

    version = "unknown"
    tactics: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version", version)
        if obj.get("type") == "x-mitre-tactic" and not obj.get("revoked"):
            ext = next(r for r in obj["external_references"] if r.get("source_name") == "mitre-attack")
            tactics[obj["x_mitre_shortname"]] = {
                "tactic_id": ext["external_id"],
                "name": obj["name"],
                "shortname": obj["x_mitre_shortname"],
            }

    techniques: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None
        )
        if not ext:
            continue
        tid = ext["external_id"]
        desc = (obj.get("description") or "").split("\n")[0]
        techniques[tid] = {
            "technique_id": tid,
            "name": obj["name"],
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                        if p.get("kill_chain_name") == "mitre-attack"],
            "description": desc[:600],
            "url": ext.get("url"),
        }

    # Sub-technique display names follow ATT&CK convention "Parent: Sub".
    for tid, t in techniques.items():
        if t["is_subtechnique"]:
            parent = techniques.get(tid.split(".")[0])
            if parent:
                t["name"] = f"{parent['name']}: {t['name']}"

    return {
        "source": BUNDLE_URL,
        "attack_version": version,
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="rebuild catalog from existing bundle")
    args = parser.parse_args()
    if not args.offline or not BUNDLE_PATH.exists():
        download()
    catalog = build_catalog()
    CATALOG_PATH.write_text(json.dumps(catalog, indent=1))
    print(
        f"Wrote {CATALOG_PATH}: ATT&CK v{catalog['attack_version']}, "
        f"{len(catalog['techniques'])} techniques, {len(catalog['tactics'])} tactics"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
