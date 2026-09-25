"""Entity / attack graph for one incident (Cytoscape-ready)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.services.context import ContextStore

MAX_NODES = 200
MIN_RARITY = 0.1  # ubiquitous infrastructure (DNS, IdP) is hidden unless central to the incident


def build_graph(view: dict[str, Any], alerts: list[dict[str, Any]], ctx: ContextStore) -> dict[str, Any]:
    rarity = {(e["type"], e["value"]): e["rarity"] for e in view.get("entities", [])}
    stage_of: dict[str, str] = {}
    for s in view.get("attack_stages", []):
        for aid in s["alert_ids"]:
            stage_of[aid] = s["label"]

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def node(etype: str, value: str | None, role: str) -> str | None:
        if not value:
            return None
        if rarity.get((etype, value), 1.0) < MIN_RARITY:
            return None
        nid = f"{etype}:{value}"
        n = nodes.get(nid)
        if n is None:
            n = nodes[nid] = {"id": nid, "type": etype, "label": value, "role": role, "alert_ids": [],
                              "alert_count": 0, "rarity": rarity.get((etype, value)), "stages": set(),
                              "context": _context(etype, value, ctx)}
        return nid

    def link(a: str | None, b: str | None, rel: str, alert: dict[str, Any]) -> None:
        if not a or not b or a == b:
            return
        key = (a, b, rel)
        e = edges.get(key)
        if e is None:
            e = edges[key] = {"id": f"{a}->{b}:{rel}", "source": a, "target": b, "relation": rel,
                              "alert_ids": [], "alert_count": 0}
        e["alert_count"] += 1
        if len(e["alert_ids"]) < 50:
            e["alert_ids"].append(alert["alert_id"])

    def ip_node(ip: str | None, alert_host: str | None, role: str) -> str | None:
        """Internal IPs resolve to their host (CMDB); an alert host's own IP is not a separate entity."""
        if not ip or rarity.get(("ip", ip), 1.0) < MIN_RARITY:
            return None
        resolved = ctx.ip_to_host.get(ip)
        if resolved:
            if resolved == alert_host:
                return None
            return node("host", resolved, role)
        return node("ip", ip, role)

    for a in alerts:
        src = ip_node(a.get("src_ip"), a.get("host"), "source")
        user = node("user", a.get("user"), "actor")
        host = node("host", a.get("host"), "device")
        proc = node("process", a.get("process"), "process")
        res = node("resource", a.get("resource"), "target")
        dst = ip_node(a.get("dst_ip"), a.get("host"), "destination") if a.get("dst_ip") != a.get("src_ip") else None
        for nid in (src, user, host, proc, res, dst):
            if nid:
                n = nodes[nid]
                n["alert_count"] += 1
                if len(n["alert_ids"]) < 50:
                    n["alert_ids"].append(a["alert_id"])
                if a["alert_id"] in stage_of:
                    n["stages"].add(stage_of[a["alert_id"]])
        link(src, user or host, "authenticates as" if user else "connects to", a)
        link(user, host, "active on", a)
        link(host, proc, "runs", a)
        link(proc or host or user, res, "accesses", a)
        if dst:
            link(res or host or user, dst, "hosted on" if res else "connects to", a)

    ranked = sorted(nodes.values(), key=lambda n: -n["alert_count"])
    aggregated = len(ranked) > MAX_NODES
    keep = {n["id"] for n in ranked[:MAX_NODES]}
    out_nodes = []
    for n in ranked[:MAX_NODES]:
        n["stages"] = sorted(n["stages"])
        out_nodes.append(n)
    out_edges = [e for e in edges.values() if e["source"] in keep and e["target"] in keep]
    degree: dict[str, int] = defaultdict(int)
    for e in out_edges:
        degree[e["source"]] += 1
        degree[e["target"]] += 1
    for n in out_nodes:
        n["degree"] = degree[n["id"]]
    return {"incident_id": view["incident_id"], "nodes": out_nodes, "edges": out_edges,
            "aggregated": aggregated, "total_entities": len(nodes)}


def _context(etype: str, value: str, ctx: ContextStore) -> dict[str, Any]:
    if etype == "user" and (u := ctx.user(value)):
        return {"privilege": u.get("privilege"), "department": u.get("department"),
                "is_service": u.get("is_service")}
    if etype == "host" and (h := ctx.host(value)):
        return {"criticality": h.get("criticality"), "role": h.get("role"), "environment": h.get("environment")}
    if etype == "resource" and (r := ctx.resource(value)):
        return {"criticality": r.get("criticality"), "owner": r.get("owner")}
    if etype == "ip":
        internal = value.startswith(("10.", "192.168.", "172."))
        return {"internal": internal, "host": ctx.ip_to_host.get(value)}
    return {}
