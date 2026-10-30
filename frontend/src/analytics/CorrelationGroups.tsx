import { Empty, Panel, TableWrap, Tag, fmt, pct, tdCls, thCls } from "../components/ui";
import { useApi } from "../services/api";
import type { DefenseState } from "../services/types";

/** Agent 4: groups of suspicious flows, built only from records already observed in the replay. */
export function CorrelationGroups() {
  const { data } = useApi<DefenseState>("/defense?member_limit=5&group_limit=100", 2000);
  if (!data) return null;
  return (
    <Panel title="Agent 4: temporal correlation" hint="Groups use observed endpoints inside a sliding window. Later records are never read.">
      {!data.available ? <Empty title="Off for this input">{data.unavailable_reason}</Empty> : data.groups.length ? (
        <TableWrap>
          <div className="max-h-[320px] overflow-y-auto">
            <table className="w-full text-xs num">
              <thead className="sticky top-0 bg-ink-850"><tr>{["Group", "Scope", "Members", "First", "Last", "Attack share", "Pattern", "Member records"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
              <tbody>
                {data.groups.map((g) => (
                  <tr key={g.group_id}>
                    <td className={tdCls}>{g.group_id}</td>
                    <td className={tdCls}><Tag tone={g.scope_type === "DESTINATION_IP" ? "warn" : "neutral"}>{g.scope_type === "DESTINATION_IP" ? "dst" : "src"}</Tag> {g.scope_value}</td>
                    <td className={tdCls}>{fmt(g.member_count)}</td>
                    <td className={tdCls}>{g.first_record_id}</td>
                    <td className={tdCls}>{g.last_record_id}</td>
                    <td className={tdCls}>{pct(g.evidence.attack_share, 0)}</td>
                    <td className={`${tdCls} text-text-2`}>{g.evidence.pattern}</td>
                    <td className={`${tdCls} text-text-3`}>{g.member_record_ids.join(", ")}{g.member_count > g.member_record_ids.length ? ", …" : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-[11px] text-text-3 mt-2">Latest {fmt(data.groups.length)} of {fmt(data.groups_total)} groups.</p>
        </TableWrap>
      ) : <Empty title="No groups yet">Start a replay on a file with source addresses.</Empty>}
    </Panel>
  );
}
