import cytoscape, { type Core, type ElementDefinition } from 'cytoscape'
import { Maximize2, MousePointerClick } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useEffect, useRef, useState } from 'react'
import type { GraphEdge, GraphNode, IncidentGraph } from '../types/api'
import { AlertChip, ease } from './ui'

const TYPE_STYLE: Record<string, { color: string; bg: string; shape: cytoscape.Css.NodeShape; tag: string }> = {
  ip: { color: '#d92d20', bg: '#fef3f2', shape: 'round-diamond', tag: 'IP' },
  user: { color: '#7a5af8', bg: '#f4f3ff', shape: 'ellipse', tag: 'User' },
  host: { color: '#0f6cbd', bg: '#eff6fe', shape: 'round-rectangle', tag: 'Host' },
  process: { color: '#ef6820', bg: '#fef6ee', shape: 'round-hexagon', tag: 'Process' },
  resource: { color: '#079455', bg: '#ecfdf3', shape: 'barrel', tag: 'Data' },
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
      pos[n.id] = { x: ci * 180, y: (i - (col.length - 1) / 2) * 110 }
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
            label: n.label,
            color: internal ? '#667085' : st.color,
            bg: internal ? '#f2f4f7' : st.bg,
            shape: st.shape,
            size: 38 + 26 * Math.sqrt(n.alert_count / maxCount),
          },
        }
      }),
      ...graph.edges.map((e) => ({
        data: { id: e.id, source: e.source, target: e.target, label: `${e.relation} · ${e.alert_count}`, w: 1.2 + Math.log2(1 + e.alert_count) * 0.8 },
      })),
    ]
    const cy = cytoscape({
      container: ref.current,
      elements,
      wheelSensitivity: 0.25,
      minZoom: 0.35,
      maxZoom: 2.2,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(bg)',
            'border-color': 'data(color)',
            'border-width': 2.5,
            shape: 'data(shape)' as unknown as cytoscape.Css.NodeShape,
            width: 'data(size)',
            height: 'data(size)',
            label: 'data(label)',
            color: '#344054',
            'font-size': 12,
            'font-weight': 600,
            'font-family': 'Inter, ui-sans-serif, system-ui',
            'text-valign': 'bottom',
            'text-margin-y': 8,
            'text-background-color': '#ffffff',
            'text-background-opacity': 0.92,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'transition-property': 'border-width, background-color',
            'transition-duration': 180,
          },
        },
        { selector: 'node:selected', style: { 'border-width': 4.5, 'underlay-color': 'data(color)', 'underlay-opacity': 0.14, 'underlay-padding': 8 } },
        {
          selector: 'edge',
          style: {
            width: 'data(w)',
            'line-color': '#c2cad6',
            'target-arrow-color': '#c2cad6',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.9,
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 10,
            'font-family': 'Inter, ui-sans-serif, system-ui',
            color: '#667085',
            'text-rotation': 'autorotate',
            'text-background-color': '#fbfcfd',
            'text-background-opacity': 1,
            'text-background-padding': '2px',
          },
        },
        { selector: 'edge:selected', style: { 'line-color': '#0f6cbd', 'target-arrow-color': '#0f6cbd', color: '#0f4c83', width: 3 } },
      ],
      layout: { name: 'preset', positions: layeredPositions(graph.nodes), fit: true, padding: 48 } as cytoscape.LayoutOptions,
    })
    // Entrance: nodes fade + grow in column order, edges follow.
    cy.nodes().forEach((n) => {
      const finalSize = n.data('size')
      n.style({ opacity: 0, width: finalSize * 0.6, height: finalSize * 0.6 })
      const col = Math.round((n.position('x') ?? 0) / 180)
      n.delay(120 * Math.max(0, col)).animate({ style: { opacity: 1, width: finalSize, height: finalSize } }, { duration: 380, easing: 'ease-out-cubic' })
    })
    cy.edges().style({ opacity: 0 })
    cy.edges().delay(420).animate({ style: { opacity: 1 } }, { duration: 500 })
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
        <div ref={ref} className="dot-grid h-[440px] w-full rounded-xl border border-line" aria-label="Entity relationship graph" />
        <div className="pointer-events-none absolute left-3 top-3 flex flex-wrap gap-1.5">
          {Object.entries(TYPE_STYLE).map(([k, v]) => (
            <span key={k} className="inline-flex items-center gap-1.5 rounded-md bg-white/95 px-2 py-0.5 text-[11px] font-medium text-fg-2 shadow-[var(--shadow-xs)] ring-1 ring-line">
              <span className="h-2 w-2 rounded-full" style={{ background: v.color }} />
              {v.tag}
            </span>
          ))}
        </div>
        <button
          onClick={() => cyRef.current?.animate({ fit: { eles: cyRef.current.elements(), padding: 48 } }, { duration: 300 })}
          className="absolute right-3 top-3 inline-flex items-center gap-1 rounded-md bg-white px-2 py-1 text-xs font-medium text-fg-2 shadow-[var(--shadow-xs)] ring-1 ring-line hover:bg-subtle"
        >
          <Maximize2 className="h-3.5 w-3.5" /> Fit
        </button>
        {graph.aggregated && <div className="mt-1.5 text-xs text-fg-subtle">Showing top {graph.nodes.length} of {graph.total_entities} entities.</div>}
      </div>
      <div className="rounded-xl border border-line bg-subtle/40 p-4 text-sm">
        <AnimatePresence mode="wait">
          <motion.div key={sel ? (sel.kind === 'node' ? sel.node.id : sel.edge.id) : 'none'} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2, ease }}>
            {!sel ? (
              <div className="flex flex-col items-center py-8 text-center">
                <span className="flex h-10 w-10 items-center justify-center rounded-full bg-white shadow-[var(--shadow-xs)] ring-1 ring-line"><MousePointerClick className="h-5 w-5 text-brand-600" /></span>
                <div className="mt-3 font-semibold text-fg">Select a node or edge</div>
                <p className="mt-1 text-[13px] text-fg-subtle">Every entity and relationship links back to the source alerts that produced it. Ubiquitous infrastructure (DNS, IdP) is hidden.</p>
              </div>
            ) : sel.kind === 'node' ? (
              <div>
                <div className="text-xs font-medium capitalize text-fg-subtle">{sel.node.type} · {sel.node.role}</div>
                <div className="mt-0.5 break-all font-mono text-[15px] font-semibold text-fg">{sel.node.label}</div>
                <dl className="mt-3 space-y-1.5 text-[13px]">
                  <div className="flex justify-between"><dt className="text-fg-subtle">Alerts</dt><dd className="font-medium text-fg-2">{sel.node.alert_count}</dd></div>
                  <div className="flex justify-between"><dt className="text-fg-subtle">Rarity</dt><dd className="font-medium text-fg-2">{sel.node.rarity?.toFixed(2) ?? '—'}</dd></div>
                  {Object.entries(sel.node.context).filter(([, v]) => v !== null && v !== undefined).map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-3"><dt className="capitalize text-fg-subtle">{k.replaceAll('_', ' ')}</dt><dd className="truncate font-medium text-fg-2">{String(v)}</dd></div>
                  ))}
                </dl>
                {sel.node.stages.length > 0 && <div className="mt-3 text-xs text-fg-subtle">Stages: <span className="text-fg-2">{sel.node.stages.join(', ')}</span></div>}
              </div>
            ) : (
              <div>
                <div className="text-xs font-medium text-fg-subtle">Relationship</div>
                <div className="mt-0.5 font-mono text-[13px] text-fg">{sel.edge.source.split(':')[1]} → {sel.edge.target.split(':')[1]}</div>
                <div className="mt-1 text-[13px] text-fg-muted">{sel.edge.relation} · {sel.edge.alert_count} alerts</div>
              </div>
            )}
            {ids.length > 0 && (
              <div className="mt-4 border-t border-line pt-3">
                <div className="mb-2 text-xs font-medium text-fg-subtle">Evidence ({ids.length}{ids.length >= 50 ? '+' : ''})</div>
                <div className="scrollbar-thin flex max-h-44 flex-wrap gap-1 overflow-y-auto">
                  {ids.map((id) => <AlertChip key={id} id={id} onClick={onOpenAlert} />)}
                </div>
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  )
}
