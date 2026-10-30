import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Btn, DecisionBadge, Empty, Notice, Panel, TableWrap, fmt, tdCls, thCls } from "../components/ui";
import { post } from "../services/api";
import type { Decision, PolicyState, Simulation, Thresholds } from "../services/types";

const FIELDS: { key: keyof Thresholds; label: string; hint: string }[] = [
  { key: "allow_benign_confidence", label: "ALLOW: benign confidence", hint: "Benign flows with no other signal" },
  { key: "block_multi_signal_confidence", label: "BLOCK: attack confidence with independent support", hint: "Anomaly or campaign evidence also present" },
  { key: "block_classifier_only_confidence", label: "BLOCK: attack confidence, classifier only", hint: "No second signal, so the bar is higher" },
];
const DECISIONS: Decision[] = ["ALLOW", "BLOCK", "REVIEW"];

/** Threshold editor and what-if simulation. Applying changes the backend policy. */
export function PolicyControls({ policy, onApplied }: { policy: PolicyState | null; onApplied: () => void }) {
  const [draft, setDraft] = useState<Thresholds | null>(null);
  const [reason, setReason] = useState("");
  const [sim, setSim] = useState<Simulation | null>(null);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  useEffect(() => {
    if (policy && !draft) setDraft(policy.thresholds);
  }, [policy, draft]);

  const dirty = draft && policy && FIELDS.some((f) => draft[f.key] !== policy.thresholds[f.key]);

  const simulate = async () => {
    if (!draft) return;
    setBusy(true); setProblem(null);
    try {
      setSim(await post<Simulation>("/policy/simulate", { thresholds: draft, max_examples: 25 }));
    } catch (e) { setProblem((e as Error).message); } finally { setBusy(false); }
  };
  const apply = async () => {
    if (!draft) return;
    setBusy(true); setProblem(null);
    try {
      await post("/policy/configure", { thresholds: draft, reason });
      setSim(null); setReason("");
      onApplied();
    } catch (e) { setProblem((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <>
      {problem && <Notice tone="crit" title="Request failed">{problem}</Notice>}
      <div className="grid lg:grid-cols-2 gap-3">
        <Panel title="Policy thresholds" hint="Defaults were set on internal holdout data. Simulate first; applying affects future decisions and the batch view.">
          {draft ? (
            <div className="space-y-4">
              {FIELDS.map((f) => (
                <div key={f.key}>
                  <label htmlFor={f.key} className="flex justify-between gap-3 text-xs">
                    <span className="text-text-1">{f.label}</span>
                    <span className="num text-accent">{draft[f.key].toFixed(3)}</span>
                  </label>
                  <input id={f.key} type="range" min={0.5} max={1} step={0.001} value={draft[f.key]}
                    onChange={(e) => setDraft({ ...draft, [f.key]: Number(e.target.value) })} className="w-full accent-sky-400 mt-1" />
                  <p className="text-[11px] text-text-3">{f.hint}. Calibrated default: {policy?.calibrated[f.key]}</p>
                </div>
              ))}
              <input aria-label="Reason for change" placeholder="Reason for change (logged)" value={reason} onChange={(e) => setReason(e.target.value)} className="w-full bg-ink-800 border border-ink-600 rounded-md px-2 py-1.5" />
              <div className="flex flex-wrap gap-2">
                <Btn tone="primary" onClick={simulate} disabled={busy}>Simulate what-if</Btn>
                <Btn onClick={apply} disabled={busy || !dirty}>Apply thresholds</Btn>
                <Btn onClick={() => { setDraft(policy!.thresholds); setSim(null); }} disabled={!dirty}>Reset</Btn>
              </div>
            </div>
          ) : <p className="text-text-3">Loading…</p>}
        </Panel>
        <Panel title="What-if result" hint={sim ? `${fmt(sim.flows_evaluated)} validation flows re-decided; stored results are unchanged` : "Run a simulation to compare decisions"}>
          {sim ? (
            <div className="space-y-3">
              <table className="w-full num">
                <thead><tr>{["", "Before", "After", "Change"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
                <tbody>
                  {DECISIONS.map((d) => (
                    <tr key={d}>
                      <td className={tdCls}><DecisionBadge decision={d} /></td>
                      <td className={tdCls}>{fmt(sim.decisions_before[d])}</td>
                      <td className={tdCls}>{fmt(sim.decisions_after[d])}</td>
                      <td className={tdCls}>{sim.decisions_after[d] - sim.decisions_before[d] > 0 ? "+" : ""}{fmt(sim.decisions_after[d] - sim.decisions_before[d])}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="text-xs text-text-2">{fmt(sim.changed)} decisions change.{" "}
                {Object.entries(sim.transitions).map(([k, v]) => `${k}: ${fmt(v)}`).join(", ")}</p>
              {sim.examples.length > 0 && (
                <TableWrap>
                  <table className="w-full text-xs num">
                    <thead><tr>{["Flow", "Change", "Class", "Confidence", "Anomaly", "Evidence"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
                    <tbody>
                      {sim.examples.slice(0, 8).map((e) => (
                        <tr key={e.flow_id}>
                          <td className={tdCls}><Link className="text-accent hover:underline" to={`/investigate?flow=${e.flow_id}`}>{e.flow_id}</Link></td>
                          <td className={tdCls}>{e.before} → {e.after}</td>
                          <td className={tdCls}>{e.final_class}</td>
                          <td className={tdCls}>{e.confidence.toFixed(4)}</td>
                          <td className={tdCls}>{e.anomaly_score.toFixed(3)}</td>
                          <td className={tdCls}>{e.evidence_status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableWrap>
              )}
            </div>
          ) : <Empty title="No simulation yet" />}
        </Panel>
      </div>
    </>
  );
}
