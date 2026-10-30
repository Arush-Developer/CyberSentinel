import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { EvidenceGraph } from "../evidence-graph/EvidenceGraph";
import { BarList, CLASS_COLOR, Btn, ClassTag, DecisionBadge, Empty, Notice, Page, Panel, TableWrap, Tag, fmt, tdCls, thCls } from "../components/ui";
import { useApi } from "../services/api";
import { CLASSES, type FlowDetail, type FlowRow } from "../services/types";
import { HypothesisPanel } from "./HypothesisPanel";

const FILTERS: Record<string, { label: string; query: string }> = {
  disagree: { label: "Agents disagree", query: "disagree=true" },
  anomaly: { label: "Anomaly only", query: "evidence_status=ANOMALY_ONLY" },
  review: { label: "Decision: review", query: "decision=REVIEW" },
  block: { label: "Decision: block", query: "decision=BLOCK" },
};

const SUPPORT_TONE = { attack: "crit", benign: "good", neutral: "neutral" } as const;

function FlowList({ selected, onSelect }: { selected: string | null; onSelect: (id: string) => void }) {
  const [filter, setFilter] = useState("disagree");
  const [search, setSearch] = useState("");
  const query = `/flows?scope=historical&limit=60&${FILTERS[filter].query}${search ? `&search=${encodeURIComponent(search)}` : ""}`;
  const { data, error } = useApi<{ total: number; items: FlowRow[] }>(query);
  useEffect(() => {
    if (!selected && data?.items[0]) onSelect(data.items[0].flow_id);
  }, [data, selected, onSelect]);
  return (
    <Panel title="Flows to investigate" hint={data ? `${fmt(data.total)} match` : undefined} className="lg:sticky lg:top-4">
      <div className="flex flex-wrap gap-1.5 mb-2">
        <select aria-label="Filter flows" value={filter} onChange={(e) => setFilter(e.target.value)} className="bg-ink-800 border border-ink-600 rounded-md px-2 py-1 flex-1 min-w-[120px]">
          {Object.entries(FILTERS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        <input aria-label="Search flow id" placeholder="Flow id" value={search} onChange={(e) => setSearch(e.target.value)} className="bg-ink-800 border border-ink-600 rounded-md px-2 py-1 w-24" />
      </div>
      {error && <Notice tone="crit" title="Could not load flows">{error}</Notice>}
      <ul className="max-h-[60vh] overflow-y-auto space-y-0.5">
        {data?.items.map((f) => (
          <li key={f.flow_id}>
            <button onClick={() => onSelect(f.flow_id)} className={`w-full text-left rounded px-2 py-1.5 hover:bg-ink-800 ${selected === f.flow_id ? "bg-accent/10" : ""}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="num font-medium">{f.flow_id}</span>
                <DecisionBadge decision={f.policy_decision} />
              </div>
              <div className="flex items-center justify-between gap-2 text-xs text-text-2 mt-0.5">
                <ClassTag name={f.final_class} />
                <span className="num">anomaly {f.anomaly_score.toFixed(3)}</span>
              </div>
            </button>
          </li>
        ))}
        {data && !data.items.length && <Empty title="No flows match" />}
      </ul>
    </Panel>
  );
}

function Detail({ flowId }: { flowId: string }) {
  const { data, error } = useApi<FlowDetail>(`/flows/${flowId}`);
  if (error) return <Notice tone="crit" title={`Could not load ${flowId}`}>{error}</Notice>;
  if (!data || data.flow_id !== flowId) return <p className="text-text-3">Loading {flowId}…</p>;
  const inv = data.investigation;
  return (
    <div className="space-y-3 min-w-0">
      <Panel>
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-semibold num">{data.flow_id}</h2>
          <ClassTag name={data.fusion.final_class} />
          <Tag tone="accent">{data.fusion.evidence_status}</Tag>
          <Tag tone={data.fusion.agreement === "AGREE" ? "good" : "warn"}>{data.fusion.agreement === "AGREE" ? "Agents agree" : "Agents disagree"}</Tag>
          <DecisionBadge decision={data.policy.decision} />
          <span className="text-xs text-text-3">{data.policy.decision_reason} (simulated)</span>
        </div>
        {data.replay?.action && (
          <p className="mt-2 text-xs text-text-2">
            In the last replay, Agent 5 {data.replay.action === "BLOCK" ? <>blocked this flow under <span className="text-crit num">{data.replay.applied_policy_id}</span>, activated by earlier flows.</> : "allowed this flow and analysed it."}
          </p>
        )}
        <p className="mt-3 text-text-1 leading-relaxed">{data.fusion.rationale}</p>
        <p className="mt-2 text-xs text-text-3">
          Label, shown for evaluation only and unseen by every agent: <span className="text-text-2">{data.ground_truth_evaluation_only ?? "none"}</span>
        </p>
      </Panel>
      <div className="grid xl:grid-cols-2 gap-3">
        <Panel title="Agent 1: threat detection" hint={data.threat.model_version}>
          <BarList total={1} items={CLASSES.map((c) => ({ label: c, value: data.threat.probabilities[c], color: CLASS_COLOR[c] }))} />
          <p className="text-xs text-text-3 mt-2">Bars show class probability. {data.threat.calibration_status}.</p>
        </Panel>
        <Panel title={`Agent 2: anomaly score ${data.anomaly.anomaly_score.toFixed(3)}`} hint={`${data.anomaly.is_anomaly ? "Flagged" : "Not flagged"} at threshold ${data.anomaly.threshold}. ${data.anomaly.score_meaning}.`}>
          {data.anomaly.supporting_features.length ? (
            <TableWrap>
              <table className="w-full text-xs">
                <thead><tr>{["Feature", "Measured", "Benign median", "Robust z"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
                <tbody>
                  {data.anomaly.supporting_features.map((f) => (
                    <tr key={f.feature}>
                      <td className={tdCls}>{f.feature}</td>
                      <td className={`${tdCls} num`}>{fmt(+f.measured_value.toFixed(2))}</td>
                      <td className={`${tdCls} num`}>{fmt(+f.benign_median.toFixed(2))}</td>
                      <td className={`${tdCls} num`}>{f.robust_z}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          ) : <Empty title="No feature deviates strongly from the benign baseline" />}
        </Panel>
      </div>
      <Panel title="Evidence graph" hint="How observations connect this flow to the final decision. Every node comes from this flow's measured output.">
        <EvidenceGraph nodes={data.evidence_graph.nodes} edges={data.evidence_graph.edges} height={420} />
      </Panel>
      <div className="grid xl:grid-cols-2 gap-3">
        <Panel title={inv ? `Investigation: ${inv.verdict}` : "Investigation"} hint={inv ? `${inv.planner} planner, triggers: ${inv.triggers.join(", ")}` : "No trigger fired for this flow."}>
          {inv ? (
            <ol className="space-y-3">
              {inv.tool_calls.map((c, i) => (
                <li key={i} className="border-l-2 border-ink-600 pl-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <code className="text-xs text-accent">{c.tool}</code>
                    <Tag tone={SUPPORT_TONE[c.result.supports as keyof typeof SUPPORT_TONE] ?? "neutral"}>supports: {c.result.supports}</Tag>
                    {!c.result.available && <Tag tone="warn">unavailable</Tag>}
                    <span className="text-[11px] text-text-3 num">{c.duration_ms} ms</span>
                  </div>
                  <p className="text-xs text-text-2 mt-1">{c.result.summary}</p>
                </li>
              ))}
            </ol>
          ) : <Empty title="Not investigated" />}
          {inv && inv.contradicting_observations.length > 0 && (
            <div className="mt-3"><Notice title="Contradicting observations">{inv.contradicting_observations.map((c) => <p key={c}>{c}</p>)}</Notice></div>
          )}
        </Panel>
        <HypothesisPanel data={data} />
      </div>
    </div>
  );
}

export function InvestigationWorkbench() {
  const [params, setParams] = useSearchParams();
  const selected = params.get("flow");
  const onSelect = (id: string) => setParams({ flow: id }, { replace: true });
  return (
    <Page title="Investigation Workbench" subtitle="Follow a suspicious flow through both agents, the investigation tools and the final decision."
      actions={selected ? <Btn onClick={() => setParams({})}>Clear selection</Btn> : undefined}>
      <div className="grid lg:grid-cols-[280px_1fr] gap-3 items-start">
        <FlowList selected={selected} onSelect={onSelect} />
        {selected ? <Detail flowId={selected} /> : <Empty title="Select a flow" />}
      </div>
    </Page>
  );
}
