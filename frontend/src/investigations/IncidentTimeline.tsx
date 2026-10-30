import { Link } from "react-router-dom";
import { Empty, Panel, Tag, fmt } from "../components/ui";
import type { Incident } from "../services/types";

export function IncidentTimeline({ incidents, total, scope }: { incidents: Incident[]; total: number; scope: string }) {
  return (
    <Panel title="Recent incidents" hint={`${fmt(total)} in ${scope === "replay" ? "the current replay" : "the batch analysis of the validation set"}`}>
      {incidents.length ? (
        <ul className="divide-y divide-ink-700/70">
          {incidents.map((inc) => (
            <li key={inc.incident_id} className="py-2 flex flex-wrap items-center gap-x-3 gap-y-1">
              <Tag tone={inc.severity === "high" ? "crit" : "warn"}>{inc.severity}</Tag>
              <span className="font-medium">{inc.title}</span>
              <span className="text-text-3 num text-xs">{fmt(inc.flow_count)} flows</span>
              {inc.flow_ids[0] && <Link className="text-accent text-xs ml-auto hover:underline" to={`/investigate?flow=${inc.flow_ids[0]}`}>Investigate {inc.flow_ids[0]}</Link>}
            </li>
          ))}
        </ul>
      ) : <Empty title="No incidents" />}
    </Panel>
  );
}
