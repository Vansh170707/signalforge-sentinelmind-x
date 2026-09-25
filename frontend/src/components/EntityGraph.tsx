import cytoscape, { type Core, type ElementDefinition } from 'cytoscape'
import { useEffect, useRef, useState } from 'react'
import type { GraphEdge, GraphNode, IncidentGraph } from '../types/api'
import { AlertChip } from './ui'

const TYPE_STYLE: Record<string, { color: string; shape: cytoscape.Css.NodeShape; tag: string }> = {
  ip: { color: '#f43f5e', shape: 'diamond', tag: 'IP' },
  user: { color: '#a78bfa', shape: 'ellipse', tag: 'USER' },
  host: { color: '#22d3ee', shape: 'round-rectangle', tag: 'HOST' },
  process: { color: '#fb923c', shape: 'hexagon', tag: 'PROC' },
  resource: { color: '#facc15', shape: 'barrel', tag: 'DATA' },
}

/** Left-to-right kill-chain layout: source -> identity -> host -> process -> data -> destination. */
function layer(n: GraphNode): number {
  if (n.role === 'source') return 0
  if (n.type === 'user') return 1
  if (n.type === 'host' && n.role === 'device') return 2
  if (n.type === 'process') return 3
  if (n.type === 'resource') return 4
  return 5
}

function layeredPositions(nodes: GraphNode[]): Record<string, { x: number; y: number }> {
  const cols = new Map<number, GraphNode[]>()
  nodes.forEach((n) => cols.set(layer(n), [...(cols.get(layer(n)) ?? []), n]))
  const used = [...cols.keys()].sort((a, b) => a - b)
  const pos: Record<string, { x: number; y: number }> = {}
  used.forEach((l, ci) => {
    const col = cols.get(l)!.sort((a, b) => b.alert_count - a.alert_count)
    col.forEach((n, i) => {
      pos[n.id] = { x: ci * 175, y: (i - (col.length - 1) / 2) * 105 + (ci % 2) * 18 }
    })
  })
  return pos
}

type Selection = { kind: 'node'; node: GraphNode } | { kind: 'edge'; edge: GraphEdge } | null

export function EntityGraph({ graph, onOpenAlert }: { graph: IncidentGraph; onOpenAlert: (id: string) => void }) {
  const ref = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const [sel, setSel] = useState<Selection>(null)

  useEffect(() => {
    if (!ref.current) return
    const maxCount = Math.max(1, ...graph.nodes.map((n) => n.alert_count))
    const elements: ElementDefinition[] = [
      ...graph.nodes.map((n) => {
        const internal = n.type === 'ip' && (n.context as { internal?: boolean }).internal
        const st = TYPE_STYLE[n.type] ?? TYPE_STYLE.host
        return {
          data: {
            id: n.id,
            label: `${st.tag}\n${n.label}`,
            color: internal ? '#64748b' : st.color,
            shape: st.shape,
            size: 40 + 30 * Math.sqrt(n.alert_count / maxCount),
          },
        }
      }),
      ...graph.edges.map((e) => ({
        data: { id: e.id, source: e.source, target: e.target, label: `${e.relation} ×${e.alert_count}`, w: 1 + Math.log2(1 + e.alert_count) },
      })),
    ]
    const cy = cytoscape({
      container: ref.current,
      elements,
      wheelSensitivity: 0.25,
      minZoom: 0.3,
      maxZoom: 2.5,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            'background-opacity': 0.18,
            'border-color': 'data(color)',
            'border-width': 2,
            shape: 'data(shape)' as unknown as cytoscape.Css.NodeShape,
            width: 'data(size)',
            height: 'data(size)',
            label: 'data(label)',
            color: '#e2e8f0',
            'font-size': 13,
            'font-family': 'JetBrains Mono, ui-monospace, monospace',
            'text-wrap': 'wrap',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-outline-color': '#0b111b',
            'text-outline-width': 3,
          },
        },
        { selector: 'node:selected', style: { 'border-width': 4, 'background-opacity': 0.4, 'border-color': '#e0f2fe' } },
        {
          selector: 'edge',
          style: {
            width: 'data(w)',
            'line-color': '#3d506c',
            'target-arrow-color': '#3d506c',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 8,
            color: '#94a3b8',
            'text-rotation': 'autorotate',
            'text-background-color': '#0b111b',
            'text-background-opacity': 0.9,
            'text-background-padding': '2px',
          },
        },
        { selector: 'edge:selected', style: { 'line-color': '#22d3ee', 'target-arrow-color': '#22d3ee', color: '#e0f2fe' } },
      ],
      layout: { name: 'preset', positions: layeredPositions(graph.nodes), fit: true, padding: 40 } as cytoscape.LayoutOptions,
    })
    cy.on('tap', 'node', (evt) => {
      const n = graph.nodes.find((x) => x.id === evt.target.id())
      if (n) setSel({ kind: 'node', node: n })
    })
    cy.on('tap', 'edge', (evt) => {
      const e = graph.edges.find((x) => x.id === evt.target.id())
      if (e) setSel({ kind: 'edge', edge: e })
    })
    cy.on('tap', (evt) => {
      if (evt.target === cy) setSel(null)
    })
    cyRef.current = cy
    return () => cy.destroy()
  }, [graph])

  const ids = sel?.kind === 'node' ? sel.node.alert_ids : sel?.kind === 'edge' ? sel.edge.alert_ids : []
  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_300px]">
      <div className="relative">
        <div ref={ref} className="h-[420px] w-full rounded-lg border border-ink-700 bg-[radial-gradient(circle_at_center,#0f1724_0%,#070b12_75%)]" aria-label="Entity relationship graph" />
        <div className="pointer-events-none absolute left-3 top-3 flex flex-wrap gap-2 text-[10px]">
          {Object.entries(TYPE_STYLE).map(([k, v]) => (
            <span key={k} className="rounded bg-ink-900/90 px-1.5 py-0.5 font-mono ring-1 ring-ink-700" style={{ color: v.color }}>{v.tag}</span>
          ))}
        </div>
        <button
          onClick={() => cyRef.current?.fit(undefined, 30)}
          className="absolute right-3 top-3 rounded bg-ink-900/90 px-2 py-1 text-[11px] text-slate-300 ring-1 ring-ink-700 hover:text-white"
        >
          Fit
        </button>
        {graph.aggregated && <div className="mt-1 text-[11px] text-slate-500">Showing top {graph.nodes.length} of {graph.total_entities} entities.</div>}
      </div>
      <div className="rounded-lg border border-ink-700 bg-ink-850 p-3 text-sm">
        {!sel ? (
          <div className="text-slate-500">
            <div className="font-medium text-slate-300">Click a node or edge</div>
            <p className="mt-1 text-xs">Every entity and relationship links back to the source alerts that produced it. Ubiquitous infrastructure (DNS, IdP) is hidden.</p>
          </div>
        ) : sel.kind === 'node' ? (
          <div>
            <div className="text-[11px] uppercase tracking-wide text-slate-500">{sel.node.type} · {sel.node.role}</div>
            <div className="break-all font-mono text-base font-semibold text-slate-100">{sel.node.label}</div>
            <div className="mt-2 space-y-0.5 text-xs text-slate-400">
              <div>{sel.node.alert_count} alerts · rarity {sel.node.rarity?.toFixed(2) ?? '—'}</div>
              {Object.entries(sel.node.context).filter(([, v]) => v !== null && v !== undefined).map(([k, v]) => (
                <div key={k}>{k}: <span className="text-slate-300">{String(v)}</span></div>
              ))}
              {sel.node.stages.length > 0 && <div>stages: <span className="text-slate-300">{sel.node.stages.join(', ')}</span></div>}
            </div>
          </div>
        ) : (
          <div>
            <div className="text-[11px] uppercase tracking-wide text-slate-500">relationship</div>
            <div className="font-mono text-sm text-slate-100">{sel.edge.source} → {sel.edge.target}</div>
            <div className="mt-1 text-xs text-slate-400">{sel.edge.relation} · {sel.edge.alert_count} alerts</div>
          </div>
        )}
        {ids.length > 0 && (
          <div className="mt-3">
            <div className="mb-1 text-[11px] uppercase tracking-wide text-slate-500">Evidence ({ids.length}{ids.length >= 50 ? '+' : ''})</div>
            <div className="scrollbar-thin flex max-h-48 flex-wrap gap-1 overflow-y-auto">
              {ids.map((id) => <AlertChip key={id} id={id} onClick={onOpenAlert} />)}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
