import { useState } from "react";
import { Notice, Panel, Tag, fmt, tdCls } from "../components/ui";
import { useApi } from "../services/api";

interface AuditEvent { event_id: number; time: number; kind: string; [key: string]: unknown }

const AUDIT_KINDS = ["", "policy_change", "policy_simulation", "replay_control", "tool_call", "investigation_finished", "system"];
function auditDetail(event: AuditEvent) {
  const { event_id: _id, time: _time, kind: _kind, ...rest } = event;
  return Object.entries(rest).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`).join("  ·  ");
}

export function AuditLogs() {
  const [kind, setKind] = useState("");
  const audit = useApi<{ total: number; items: AuditEvent[] }>(`/audit?limit=60${kind ? `&kind=${kind}` : ""}`, 3000);
  return (
    <Panel title="Audit log" hint={audit.data ? `${fmt(audit.data.total)} events recorded` : undefined}
      actions={
        <select aria-label="Filter audit events" value={kind} onChange={(e) => setKind(e.target.value)} className="bg-ink-800 border border-ink-600 rounded-md px-2 py-1 text-xs">
          {AUDIT_KINDS.map((k) => <option key={k} value={k}>{k || "All events"}</option>)}
        </select>
      }>
      {audit.error && <Notice tone="crit" title="Could not load audit log">{audit.error}</Notice>}
      <div className="max-h-[340px] overflow-y-auto">
        <table className="w-full text-xs">
          <tbody>
            {audit.data?.items.map((e) => (
              <tr key={e.event_id} className="align-top">
                <td className={`${tdCls} num text-text-3`}>{new Date(e.time * 1000).toLocaleTimeString()}</td>
                <td className={tdCls}><Tag>{e.kind}</Tag></td>
                <td className="py-1.5 border-t border-ink-700/70 text-text-2 break-all">{auditDetail(e)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
