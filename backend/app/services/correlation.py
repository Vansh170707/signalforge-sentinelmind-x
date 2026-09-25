"""Explainable graph correlation (blueprint section 14).

1. Candidate generation: index alerts by each meaningful entity; pair alerts that share an entity and
   fall inside the correlation window (bounded neighbours per alert -> no O(n^2)).
2. Weighted edge score:
     0.22 user + 0.18 host + 0.14 src_ip + 0.08 dst/resource + 0.12 time_proximity
     + 0.12 behavior_compatibility + 0.08 severity_coherence + 0.06 semantic_similarity
   time_proximity = exp(-delta_minutes / 15). Shared-entity terms use inverse-frequency weights.
3. Connected components over accepted edges (score >= threshold).
4. Anti-megacluster: oversized components are re-cut at progressively stricter thresholds, then by
   modularity communities, and merges into large groups require at least one strong relation.
Every membership keeps its strongest supporting edge and human-readable reasons.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from app.schemas.alerts import CanonicalAlert
from app.services.catalog import ALERT_TYPES, SEQUENCES
from app.services.embeddings import TitleSimilarity
from app.services.entities import EntityStats, entity_key

WEIGHTS = {
    "user": 0.22, "host": 0.18, "src_ip": 0.14, "dst": 0.08,
    "time": 0.12, "behavior": 0.12, "severity": 0.08, "semantic": 0.06,
}
MIN_ENTITY_WEIGHT = 0.12  # entities below this are too common to create candidates
STRONG_EDGE = 0.60


@dataclass
class CorrelationConfig:
    window_minutes: float = 30.0
    threshold: float = 0.40  # tuned on labelled demo ground truth (blueprint start: 0.45)
    max_component: int = 300
    max_neighbors: int = 30
    version: str = "c1"


@dataclass
class Edge:
    a: int
    b: int
    score: float
    reasons: list[str]
    components: dict[str, float]


@dataclass
class Membership:
    alert_index: int
    score: float
    linked_index: int | None
    reasons: list[str]


@dataclass
class Cluster:
    members: list[int]
    memberships: dict[int, Membership]
    edges: list[Edge]
    confidence: float


@dataclass
class CorrelationResult:
    clusters: list[Cluster]
    stats: dict[str, Any] = field(default_factory=dict)


def family(alert_type: str) -> str:
    spec = ALERT_TYPES.get(alert_type)
    return spec.family if spec else "other"


def stage(alert_type: str) -> str | None:
    spec = ALERT_TYPES.get(alert_type)
    return spec.stage if spec else None


def behavior_compatibility(a: CanonicalAlert, b: CanonicalAlert) -> tuple[float, str | None]:
    if a.alert_type == b.alert_type:
        return 0.6, f"repeated behavior {a.alert_type}"
    fa, fb = family(a.alert_type), family(b.alert_type)
    first, second = (fa, fb) if a.timestamp <= b.timestamp else (fb, fa)
    if (first, second) in SEQUENCES:
        return 1.0, f"known sequence {first} -> {second}"
    if (second, first) in SEQUENCES:
        return 0.7, f"related behaviors {second} / {first}"
    if fa == fb:
        return 0.5, f"same behavior family {fa}"
    if stage(a.alert_type) is None and stage(b.alert_type) is None:
        return 0.3, None
    return 0.1, None


def _shared(alert_a: CanonicalAlert, alert_b: CanonicalAlert, stats: EntityStats,
            ip_to_host: dict[str, str] | None = None) -> tuple[dict[str, float], list[str]]:
    comps: dict[str, float] = {}
    reasons: list[str] = []
    if alert_a.user and alert_a.user == alert_b.user:
        w = stats.weight(entity_key("user", alert_a.user))
        comps["user"] = w
        reasons.append(f"shared user {alert_a.user} (rarity {w:.2f})")
    if alert_a.host and alert_a.host == alert_b.host:
        w = stats.weight(entity_key("host", alert_a.host))
        comps["host"] = w
        reasons.append(f"shared host {alert_a.host} (rarity {w:.2f})")
    elif ip_to_host:
        # Host pivot: one alert originates from the other alert's host (lateral movement).
        for x, y in ((alert_a, alert_b), (alert_b, alert_a)):
            if x.host and y.src_ip and ip_to_host.get(y.src_ip) == x.host:
                w = stats.weight(entity_key("host", x.host))
                comps["host"] = w
                reasons.append(f"pivot from host {x.host} via {y.src_ip} (rarity {w:.2f})")
                break
    if alert_a.src_ip and alert_a.src_ip == alert_b.src_ip:
        w = stats.weight(entity_key("ip", alert_a.src_ip))
        comps["src_ip"] = w
        reasons.append(f"shared source IP {alert_a.src_ip} (rarity {w:.2f})")
    dst_w = 0.0
    if alert_a.dst_ip and alert_a.dst_ip == alert_b.dst_ip:
        dst_w = stats.weight(entity_key("ip", alert_a.dst_ip))
        if dst_w >= MIN_ENTITY_WEIGHT:
            reasons.append(f"shared destination {alert_a.dst_ip} (rarity {dst_w:.2f})")
    if alert_a.resource and alert_a.resource == alert_b.resource:
        rw = stats.weight(entity_key("resource", alert_a.resource))
        if rw > dst_w:
            dst_w = rw
        reasons.append(f"shared resource {alert_a.resource} (rarity {rw:.2f})")
    if dst_w:
        comps["dst"] = dst_w
    return comps, reasons


def edge_score(a: CanonicalAlert, b: CanonicalAlert, stats: EntityStats, sim: TitleSimilarity,
               ip_to_host: dict[str, str] | None = None) -> tuple[float, dict[str, float], list[str]]:
    comps, reasons = _shared(a, b, stats, ip_to_host)
    delta_min = abs((a.timestamp - b.timestamp).total_seconds()) / 60.0
    comps["time"] = math.exp(-delta_min / 15.0)
    comps["behavior"], why = behavior_compatibility(a, b)
    comps["severity"] = 1.0 - abs(a.severity_score - b.severity_score) / 100.0
    comps["semantic"] = sim.similarity(a.title, b.title)
    score = sum(WEIGHTS[k] * v for k, v in comps.items())
    reasons.append(f"{delta_min:.1f} min apart")
    if why:
        reasons.append(why)
    return min(1.0, score), comps, reasons


def _is_strong(edge: Edge) -> bool:
    c = edge.components
    rare_entity = max(c.get("user", 0), c.get("host", 0), c.get("src_ip", 0)) >= 0.45
    chain = c.get("behavior", 0) >= 1.0
    return edge.score >= STRONG_EDGE or rare_entity or chain


def correlate(alerts: list[CanonicalAlert], stats: EntityStats, cfg: CorrelationConfig | None = None,
              ip_to_host: dict[str, str] | None = None) -> CorrelationResult:
    cfg = cfg or CorrelationConfig()
    n = len(alerts)
    order = sorted(range(n), key=lambda i: alerts[i].timestamp)
    ts = [alerts[i].timestamp.timestamp() / 60.0 for i in range(n)]
    sim = TitleSimilarity([a.title for a in alerts])

    # 1) candidate generation via entity index
    index: dict[str, list[int]] = defaultdict(list)
    for i in order:
        a = alerts[i]
        for fld, etype in (("user", "user"), ("host", "host"), ("src_ip", "ip"), ("dst_ip", "ip"),
                           ("resource", "resource")):
            v = getattr(a, fld)
            if not v:
                continue
            k = entity_key(etype, v)
            if stats.weight(k) >= MIN_ENTITY_WEIGHT:
                index[k].append(i)
        # Pivot index: an alert whose source IP resolves to a host joins that host's candidate list.
        if ip_to_host and a.src_ip and ip_to_host.get(a.src_ip) not in (None, a.host):
            k = entity_key("host", ip_to_host[a.src_ip])
            if stats.weight(k) >= MIN_ENTITY_WEIGHT:
                index[k].append(i)
    candidates: set[tuple[int, int]] = set()
    for idxs in index.values():
        for pos, i in enumerate(idxs):
            added = 0
            for j in idxs[pos + 1:]:
                if ts[j] - ts[i] > cfg.window_minutes or added >= cfg.max_neighbors:
                    break
                candidates.add((i, j) if i < j else (j, i))
                added += 1

    # 2) score edges
    edges: list[Edge] = []
    for i, j in candidates:
        s, comps, reasons = edge_score(alerts[i], alerts[j], stats, sim, ip_to_host)
        if s >= cfg.threshold:
            edges.append(Edge(i, j, round(s, 4), reasons, comps))

    # 3) connected components
    g = nx.Graph()
    g.add_nodes_from(range(n))
    for e in edges:
        g.add_edge(e.a, e.b, weight=e.score, edge=e)

    # 4) anti-megacluster splitting
    groups: list[set[int]] = []
    splits = 0
    for comp in nx.connected_components(g):
        if len(comp) <= cfg.max_component:
            groups.append(set(comp))
            continue
        splits += 1
        groups.extend(_split_component(g.subgraph(comp).copy(), cfg))

    clusters = [_build_cluster(g, grp, alerts) for grp in groups]
    clusters.sort(key=lambda c: min(alerts[i].timestamp for i in c.members))
    stats_out = {
        "alerts": n,
        "candidate_pairs": len(candidates),
        "accepted_edges": len(edges),
        "clusters": len(clusters),
        "singletons": sum(1 for c in clusters if len(c.members) == 1),
        "megacluster_splits": splits,
        "semantic_backend": sim.backend,
        "threshold": cfg.threshold,
        "window_minutes": cfg.window_minutes,
        "version": cfg.version,
    }
    return CorrelationResult(clusters=clusters, stats=stats_out)


def _split_component(sub: nx.Graph, cfg: CorrelationConfig) -> list[set[int]]:
    """Re-cut an oversized component: stricter threshold first, then require strong edges,
    finally modularity communities. Returns groups each <= max_component where possible."""
    out: list[set[int]] = []
    work = [sub]
    thresholds = [cfg.threshold + d for d in (0.05, 0.10, 0.15, 0.20)]
    while work:
        h = work.pop()
        if h.number_of_nodes() <= cfg.max_component:
            out.append(set(h.nodes))
            continue
        cut = None
        for t in thresholds:
            k = nx.Graph()
            k.add_nodes_from(h.nodes)
            k.add_edges_from((u, v, d) for u, v, d in h.edges(data=True)
                             if d["weight"] >= t and _is_strong(d["edge"]))
            comps = list(nx.connected_components(k))
            if len(comps) > 1 and max(len(c) for c in comps) < h.number_of_nodes():
                cut = [k.subgraph(c).copy() for c in comps]
                break
        if cut is None:
            communities = nx.community.louvain_communities(h, weight="weight", seed=7)
            if len(communities) <= 1:
                out.append(set(h.nodes))
                continue
            cut = [h.subgraph(c).copy() for c in communities]
        work.extend(cut)
    return out


def _build_cluster(g: nx.Graph, members: set[int], alerts: list[CanonicalAlert]) -> Cluster:
    memberships: dict[int, Membership] = {}
    edges: list[Edge] = []
    for i in members:
        best: Edge | None = None
        for _, j, d in g.edges(i, data=True):
            if j not in members:
                continue
            e: Edge = d["edge"]
            if best is None or e.score > best.score:
                best = e
            if i < j:
                edges.append(e)
        if best is None:
            memberships[i] = Membership(i, 0.0, None, ["single alert; no correlated evidence in window"])
        else:
            other = best.b if best.a == i else best.a
            memberships[i] = Membership(i, best.score, other, best.reasons)
    if len(members) == 1:
        conf = 0.25
    else:
        mean_best = sum(m.score for m in memberships.values()) / len(memberships)
        conf = min(1.0, mean_best / 0.75)
    ordered = sorted(members, key=lambda i: alerts[i].timestamp)
    return Cluster(members=ordered, memberships=memberships, edges=edges, confidence=round(conf, 3))
