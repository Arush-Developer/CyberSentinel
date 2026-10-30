import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { EvidenceGraph } from "../evidence-graph/EvidenceGraph";
import { Btn, Empty, Notice, Page, Panel, TableWrap, Tag, fmt, tdCls, thCls } from "../components/ui";
import { useApi } from "../services/api";
import type { CampaignRecord, GraphEdge, GraphNode } from "../services/types";

const TYPE_COLOR: Record<string, string> = {
  VOLUMETRIC_CANDIDATE: "#d95926", DDOS_CANDIDATE: "#d55181", DOS_CANDIDATE: "#d95926",
  PORT_SCAN_CANDIDATE: "#9085e9", BRUTE_FORCE_CANDIDATE: "#199e70",
};
const recordNumber = (id: string) => Number(id.replace(/\D/g, ""));
const GRAPH_CAMPAIGNS = 8;

function Timeline({ items, selected, onSelect }: { items: CampaignRecord[]; selected?: string; onSelect: (id: string) => void }) {
  const lo = Math.min(...items.map((c) => recordNumber(c.first_observed)));
  const hi = Math.max(...items.map((c) => recordNumber(c.last_observed)));
  const span = Math.max(hi - lo, 1);
  return (
    <div className="space-y-1 max-h-[320px] overflow-y-auto pr-1">
      {items.map((c) => {
        const left = ((recordNumber(c.first_observed) - lo) / span) * 100;
        const width = Math.max(((recordNumber(c.last_observed) - recordNumber(c.first_observed)) / span) * 100, 0.6);
        return (
          <button key={c.campaign_id} onClick={() => onSelect(c.campaign_id)} title={`${c.campaign_type} on ${c.target}: ${c.first_observed} to ${c.last_observed}, ${c.flow_count} flows`}
            className={`w-full grid grid-cols-[76px_1fr] items-center gap-2 rounded px-1 py-1 text-left hover:bg-ink-800 ${selected === c.campaign_id ? "bg-ink-800" : ""}`}>
            <span className="text-[11px] num text-text-2">{c.campaign_id}</span>
            <span className="relative h-2.5 bg-ink-700/50 rounded-sm block">
              <span className="absolute h-full rounded-sm" style={{ left: `${left}%`, width: `${width}%`, background: TYPE_COLOR[c.campaign_type] ?? "#38bdf8" }} />
            </span>
          </button>
        );
      })}
    </div>
  );
}

function campaignGraph(items: CampaignRecord[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seen = new Set<string>();
  [...items].sort((a, b) => b.flow_count - a.flow_count).slice(0, GRAPH_CAMPAIGNS).forEach((c) => {
    const target = `network:${c.target}`;
    if (!seen.has(target)) {
      seen.add(target);
      nodes.push({ id: target, kind: "network", label: c.target, data: {} });
    }
    const cid = `decision:${c.campaign_id}`;
    nodes.push({ id: cid, kind: "campaign", label: `${c.campaign_id}: ${c.campaign_type}`, data: { flow_count: c.flow_count, confidence: c.confidence, windows: c.windows_observed } });
    edges.push({ id: `${cid}->${target}`, source: cid, target, relation: `${c.flow_count} flows` });
  });
  // Campaigns on the left, targets on the right.
  return { nodes: nodes.map((n) => (n.kind === "network" ? { ...n, kind: "decision" } : { ...n, kind: "flow" })), edges };
}

export function ThreatAnalytics() {
  const [scope, setScope] = useState<"replay" | "historical">("historical");
  const { data, error } = useApi<{ scope: string; mode: string; limitations: string[]; items: CampaignRecord[] }>(`/campaigns?scope=${scope}`, scope === "replay" ? 3000 : undefined);
  const ports = useApi<{ distinct_ports: number; items: { port: number; flows: number; attacks: number }[] }>(`/ports?scope=${scope}`, scope === "replay" ? 3000 : undefined);
  const [selectedId, setSelectedId] = useState<string | undefined>();
  const items = data?.items ?? [];
  const selected = items.find((c) => c.campaign_id === selectedId) ?? items[0];
  const graph = useMemo(() => campaignGraph(items), [items]);
  const portData = (ports.data?.items ?? []).map((p) => ({ port: `${p.port}`, Attack: p.attacks, Benign: p.flows - p.attacks }));

  return (
    <Page title="Attack Intelligence" subtitle="Cross-flow campaign hypotheses, built from flow behaviour without labels or classifier output."
      actions={
        <div className="flex gap-1" role="group" aria-label="Data scope">
          <Btn tone={scope === "historical" ? "primary" : "default"} onClick={() => setScope("historical")}>Whole validation set</Btn>
          <Btn tone={scope === "replay" ? "primary" : "default"} onClick={() => setScope("replay")}>Current replay</Btn>
        </div>
      }>
      {error && <Notice tone="crit" title="Could not load campaigns">{error}</Notice>}
      {data && data.mode !== "endpoint" && (
        <Notice title={`Running in ${data.mode} mode: this partition has no endpoint metadata`}>
          {data.limitations.map((l) => <p key={l}>{l}</p>)}
          <p>Endpoint detectors switch on automatically when the hidden set arrives with source_ip and destination_ip.</p>
        </Notice>
      )}
      {!items.length ? (
        <Empty title={scope === "replay" ? "No campaign hypotheses in the current replay yet" : "No campaign hypotheses"}>
          {scope === "replay" && "Start a replay in Replay Lab, or switch to the whole validation set."}
        </Empty>
      ) : (
        <>
          <div className="grid lg:grid-cols-2 gap-3">
            <Panel title="Campaign timeline" hint="Span in record order, which is a proxy for time. Click to select.">
              <Timeline items={items} selected={selected?.campaign_id} onSelect={setSelectedId} />
            </Panel>
            {selected && (
              <Panel title={`${selected.campaign_id}: ${selected.campaign_type}`} actions={<Tag tone="warn">{selected.confidence} confidence</Tag>}>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                  {[
                    ["Target", selected.target],
                    ["Flows", fmt(selected.flow_count)],
                    ["Windows", fmt(selected.windows_observed)],
                    ["Distinct sources", selected.distinct_sources ?? "Not measurable here"],
                    ["First observed", selected.first_observed],
                    ["Last observed", selected.last_observed],
                  ].map(([k, v]) => (
                    <div key={k as string}><dt className="text-text-3">{k}</dt><dd className="text-text-1 num">{v}</dd></div>
                  ))}
                </dl>
                <p className="mt-3 text-xs text-text-1">{selected.hypothesis}</p>
                <p className="mt-2 text-xs text-text-2"><span className="text-text-3">Traffic: </span>{selected.traffic_intensity}</p>
                <p className="mt-2 text-xs text-text-2"><span className="text-text-3">Basis: </span>{selected.confidence_basis}</p>
                <p className="mt-2 text-xs text-text-2"><span className="text-text-3">Uncertainty: </span>{selected.uncertainty}</p>
                {selected.contradicting_evidence.length > 0 && (
                  <p className="mt-2 text-xs text-text-2"><span className="text-text-3">Against: </span>{selected.contradicting_evidence.join(" ")}</p>
                )}
                <p className="mt-2 text-xs text-text-2"><span className="text-text-3">Relationships: </span>
                  {selected.relationships.slice(0, 4).map((r) => `${r.source ?? "unknown source"} to ${r.destination ?? "unknown host"}:${r.destination_port} (${fmt(r.flows)})`).join(", ")}
                </p>
                <div className="mt-3">
                  <p className="text-xs text-text-3 mb-1">Related flows (showing 8 of {fmt(selected.flow_count)})</p>
                  <div className="flex flex-wrap gap-1.5">
                    {selected.related_flow_ids.slice(0, 8).map((id) => (
                      <Link key={id} to={`/investigate?flow=${id}`} className="text-accent text-xs num hover:underline">{id}</Link>
                    ))}
                  </div>
                </div>
              </Panel>
            )}
          </div>
          <div className="grid lg:grid-cols-2 gap-3">
            <Panel title="Campaign to target graph" hint={items.length > GRAPH_CAMPAIGNS ? `The ${GRAPH_CAMPAIGNS} largest of ${items.length} campaigns` : undefined}>
              <EvidenceGraph nodes={graph.nodes} edges={graph.edges} height={340} />
            </Panel>
            <Panel title="Destination port distribution" hint={`Top 15 of ${fmt(ports.data?.distinct_ports)} ports, split by final class`}>
              <div className="h-[340px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={portData} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                    <CartesianGrid vertical={false} stroke="#22304a" />
                    <XAxis dataKey="port" tick={{ fill: "#a9b5c7", fontSize: 11 }} axisLine={{ stroke: "#33445f" }} tickLine={false} interval={0} angle={-35} textAnchor="end" height={46} />
                    <YAxis tick={{ fill: "#a9b5c7", fontSize: 11 }} axisLine={false} tickLine={false} width={52} tickFormatter={(v: number) => v.toLocaleString("en-IN")} />
                    <Tooltip cursor={{ fill: "#172236" }} contentStyle={{ background: "#0e1524", border: "1px solid #33445f", borderRadius: 6, fontSize: 12 }} formatter={(v: number) => v.toLocaleString("en-IN")} />
                    <Bar dataKey="Benign" stackId="a" fill="#3987e5" stroke="#111a2b" strokeWidth={1} />
                    <Bar dataKey="Attack" stackId="a" fill="#d95926" stroke="#111a2b" strokeWidth={1} radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="flex gap-4 text-xs text-text-2 mt-1">
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm bg-[#3987e5]" />Benign</span>
                <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm bg-[#d95926]" />Attack</span>
              </div>
            </Panel>
          </div>
          <Panel title="All campaign hypotheses">
            <TableWrap>
              <table className="w-full">
                <thead><tr>{["Campaign", "Type", "Target", "Flows", "Windows", "Confidence", "Intensity"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
                <tbody>
                  {items.map((c) => (
                    <tr key={c.campaign_id} className="hover:bg-ink-800 cursor-pointer" onClick={() => setSelectedId(c.campaign_id)}>
                      <td className={`${tdCls} num`}>{c.campaign_id}</td>
                      <td className={tdCls}>{c.campaign_type}</td>
                      <td className={tdCls}>{c.target}</td>
                      <td className={`${tdCls} num`}>{fmt(c.flow_count)}</td>
                      <td className={`${tdCls} num`}>{c.windows_observed}</td>
                      <td className={tdCls}>{c.confidence}</td>
                      <td className={`${tdCls} text-text-2`}>{c.traffic_intensity}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </Panel>
        </>
      )}
    </Page>
  );
}
