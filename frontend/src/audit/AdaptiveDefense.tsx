import { useState } from "react";
import { Empty, Notice, Panel, TableWrap, Tag, fmt, pct, tdCls, thCls } from "../components/ui";
import { useApi } from "../services/api";
import type { DefenseState } from "../services/types";

/** Agent 5: temporary SOURCE_IP policies from the current replay. They only ever apply to later records. */
export function AdaptiveDefense() {
  const { data, error } = useApi<DefenseState>("/defense", 2000);
  const [selected, setSelected] = useState<string | null>(null);
  if (error && !data) return <Notice tone="crit" title="Could not load Agent 5">{error}</Notice>;
  if (!data) return null;
  if (!data.available) {
    return (
      <Panel title="Agent 5: adaptive defence">
        <Empty title="Off for this input">{data.unavailable_reason}</Empty>
      </Panel>
    );
  }
  const chosen = data.policies.find((p) => p.policy_id === selected) ?? data.policies[data.policies.length - 1];
  return (
    <Panel title="Agent 5: adaptive defence" hint="Each policy starts after its triggering record and blocks only later flows from that source until it expires.">
      {data.policies.length ? (
        <div className="grid xl:grid-cols-[1fr_340px] gap-4 items-start">
          <TableWrap>
            <div className="max-h-[360px] overflow-y-auto">
              <table className="w-full text-xs num">
                <thead className="sticky top-0 bg-ink-850"><tr>{["Policy", "Scope", "Activated after", "Expires after", "Length", "Blocked", "Status"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
                <tbody>
                  {data.policies.map((p) => (
                    <tr key={p.policy_id} onClick={() => setSelected(p.policy_id)} className={`cursor-pointer hover:bg-ink-800 ${chosen?.policy_id === p.policy_id ? "bg-ink-800" : ""}`}>
                      <td className={tdCls}><button className="text-accent hover:underline" onClick={() => setSelected(p.policy_id)}>{p.policy_id}</button></td>
                      <td className={tdCls}>{p.scope_value}</td>
                      <td className={tdCls}>{p.activated_after_record_id}</td>
                      <td className={tdCls}>{p.expires_after_record_id ?? "not yet"}</td>
                      <td className={tdCls}>{fmt(p.ttl_records)}</td>
                      <td className={tdCls}>{fmt(p.blocked_records)}</td>
                      <td className={tdCls}><Tag tone={p.status === "ACTIVE" ? "crit" : "neutral"}>{p.status}</Tag></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </TableWrap>
          {chosen && (
            <div className="text-xs space-y-2">
              <p className="font-medium">{chosen.policy_id}, from group {chosen.group_id}</p>
              <p className="text-text-2 leading-relaxed">{chosen.rationale}</p>
              <p className="text-text-3">{fmt(chosen.evidence.confident_attack_flows)} attack calls, {pct(chosen.evidence.attack_share, 0)} of flows in the window, {fmt(chosen.evidence.distinct_destination_ports)} ports.</p>
            </div>
          )}
        </div>
      ) : <Empty title="No policies yet">Start a replay. Policies appear once a source has repeated attack evidence.</Empty>}
      {data.log.length > 0 && (
        <details className="mt-3 text-xs">
          <summary className="cursor-pointer text-text-2">Activation and expiry log ({fmt(data.log.length)})</summary>
          <ul className="mt-2 space-y-1 max-h-48 overflow-y-auto num text-text-2">
            {data.log.map((e) => <li key={`${e.policy_id}-${e.event}`}>{e.event} {e.policy_id} at {e.record_id} ({e.scope_value})</li>)}
          </ul>
        </details>
      )}
    </Panel>
  );
}
