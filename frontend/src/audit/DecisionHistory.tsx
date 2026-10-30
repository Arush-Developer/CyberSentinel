import { Link } from "react-router-dom";
import { Empty, Panel, TableWrap, Tag, fmt, tdCls, thCls } from "../components/ui";
import { useApi } from "../services/api";
import type { FlowRow, PolicyState } from "../services/types";

/** Flows awaiting review, past investigations and threshold changes. */
export function DecisionHistory({ history }: { history: PolicyState["history"] }) {
  const investigations = useApi<{ items: { investigation_id: string; flow_id: string; verdict: string; triggers: string[]; tools: string[] }[] }>("/investigations?limit=12", 5000);
  const decisions = useApi<{ total: number; items: FlowRow[] }>("/flows?limit=12&decision=REVIEW", 5000);
  return (
    <>
      <div className="grid lg:grid-cols-2 gap-3">
        <Panel title="Flows awaiting review" hint={decisions.data ? `${fmt(decisions.data.total)} in scope` : undefined}>
          {decisions.data?.items.length ? (
            <TableWrap>
              <table className="w-full text-xs num">
                <thead><tr>{["Flow", "Class", "Evidence", "Reason"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
                <tbody>
                  {decisions.data.items.map((f) => (
                    <tr key={f.flow_id}>
                      <td className={tdCls}><Link className="text-accent hover:underline" to={`/investigate?flow=${f.flow_id}`}>{f.flow_id}</Link></td>
                      <td className={tdCls}>{f.final_class}</td>
                      <td className={tdCls}>{f.evidence_status}</td>
                      <td className={`${tdCls} text-text-2`}>{f.policy_rule}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          ) : <Empty title="Nothing to review" />}
        </Panel>
        <Panel title="Investigation history">
          {investigations.data?.items.length ? (
            <ul className="divide-y divide-ink-700/70 text-xs">
              {investigations.data.items.map((i) => (
                <li key={i.investigation_id} className="py-1.5 flex flex-wrap items-center gap-2">
                  <Link className="text-accent num hover:underline" to={`/investigate?flow=${i.flow_id}`}>{i.flow_id}</Link>
                  <Tag tone={i.verdict === "CONFLICTING" ? "warn" : "neutral"}>{i.verdict}</Tag>
                  <span className="text-text-3 truncate">{i.tools.join(", ")}</span>
                </li>
              ))}
            </ul>
          ) : <Empty title="No investigations yet">Open a flow in the workbench, or run a replay.</Empty>}
        </Panel>
      </div>
      {history.length > 0 && (
        <Panel title="Threshold change history">
          <TableWrap>
            <table className="w-full text-xs num">
              <thead><tr>{["When", "Previous", "New", "Reason"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
              <tbody>
                {history.slice().reverse().map((h, i) => (
                  <tr key={i}>
                    <td className={tdCls}>{new Date(h.time * 1000).toLocaleTimeString()}</td>
                    <td className={tdCls}>{Object.values(h.previous).join(" / ")}</td>
                    <td className={tdCls}>{Object.values(h.new).join(" / ")}</td>
                    <td className={`${tdCls} text-text-2`}>{h.reason || "None given"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        </Panel>
      )}
    </>
  );
}
