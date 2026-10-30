import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo, useState } from "react";
import type { GraphEdge, GraphNode } from "../services/types";

const COLUMN: Record<string, number> = {
  flow: 0, network: 1, agent: 1, campaign: 1, investigation: 1, feature: 2, tool: 2, decision: 3, policy: 4,
};
const BORDER: Record<string, string> = {
  flow: "#38bdf8", agent: "#a9b5c7", feature: "#74829a", network: "#74829a", campaign: "#fbbf24",
  investigation: "#9085e9", tool: "#9085e9", decision: "#38bdf8", policy: "#34d399",
};
const COLUMN_WIDTH = 240;
const ROW_HEIGHT = 62;

/** Lays nodes out left to right: flow, evidence sources, details, fusion, decision. */
export function layoutGraph(nodes: GraphNode[], edges: GraphEdge[]): { nodes: Node[]; edges: Edge[] } {
  const rows: Record<number, number> = {};
  const counts: Record<number, number> = {};
  nodes.forEach((n) => { const col = COLUMN[n.kind] ?? 1; counts[col] = (counts[col] ?? 0) + 1; });
  const tallest = Math.max(...Object.values(counts));
  return {
    nodes: nodes.map((n) => {
      const col = COLUMN[n.kind] ?? 1;
      const row = rows[col] ?? 0;
      rows[col] = row + 1;
      return {
        id: n.id,
        position: { x: col * COLUMN_WIDTH, y: (row + (tallest - counts[col]) / 2) * ROW_HEIGHT },
        data: { label: n.label },
        sourcePosition: "right" as Node["sourcePosition"],
        targetPosition: "left" as Node["targetPosition"],
        style: {
          background: "#172236", color: "#e8edf5", border: `1px solid ${BORDER[n.kind] ?? "#33445f"}`,
          borderRadius: 6, fontSize: 11, width: 195, padding: "6px 8px", cursor: "pointer",
        },
      };
    }),
    edges: edges.map((e) => ({
      id: e.id, source: e.source, target: e.target, label: e.relation,
      style: { stroke: "#33445f" }, labelStyle: { fill: "#74829a", fontSize: 9 },
      labelBgStyle: { fill: "#111a2b" }, markerEnd: { type: MarkerType.ArrowClosed, color: "#33445f" },
    })),
  };
}

export function EvidenceGraph({ nodes, edges, height = 400 }: { nodes: GraphNode[]; edges: GraphEdge[]; height?: number }) {
  const laid = useMemo(() => layoutGraph(nodes, edges), [nodes, edges]);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  return (
    <div>
      <div style={{ height }} className="rounded-md border border-ink-700 bg-ink-900">
        <ReactFlow
          key={nodes.map((n) => n.id).join("|")}
          nodes={laid.nodes}
          edges={laid.edges}
          fitView
          minZoom={0.3}
          nodesConnectable={false}
          onNodeClick={(_, node) => setSelected(nodes.find((n) => n.id === node.id) ?? null)}
          onPaneClick={() => setSelected(null)}
          colorMode="dark"
        >
          <Background color="#22304a" gap={20} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <div className="mt-2 text-xs min-h-[34px] text-text-2">
        {selected ? (
          <div>
            <span className="text-text-1 font-medium">{selected.label}</span>{" "}
            {Object.entries(selected.data).filter(([, v]) => v !== null && v !== undefined).map(([k, v]) => (
              <span key={k} className="mr-3"><span className="text-text-3">{k}:</span> <span className="num">{typeof v === "number" ? +v.toFixed(4) : String(v)}</span></span>
            ))}
          </div>
        ) : <span className="text-text-3">Click a node to see its measured values.</span>}
      </div>
    </div>
  );
}
