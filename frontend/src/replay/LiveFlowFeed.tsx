import { Link } from "react-router-dom";
import { ClassTag, DecisionBadge, Empty, Panel, TableWrap, tdCls, thCls } from "../components/ui";
import type { ReplayFlowEvent } from "../services/types";

export function LiveFlowFeed({ flows }: { flows: ReplayFlowEvent[] }) {
  return (
    <Panel title="Live flow stream" hint="A sample of each chunk at high speed; totals above include every flow. Labels are display-only.">
      {flows.length ? (
        <TableWrap>
          <div className="max-h-[520px] overflow-y-auto">
            <table className="w-full text-xs num">
              <thead className="sticky top-0 bg-ink-850"><tr>{["Flow", "Agent 1", "Conf.", "Anomaly", "Agents", "Final", "Evidence", "Decision", "Agent 5", "Label"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
              <tbody>
                {flows.map((f) => (
                  <tr key={f.flow_id} className={f.investigation_triggered ? "bg-warn/[0.04]" : ""}>
                    <td className={tdCls}><Link className="text-accent hover:underline" to={`/investigate?flow=${f.flow_id}`}>{f.flow_id}</Link></td>
                    <td className={tdCls}>{f.threat_class}</td>
                    <td className={tdCls}>{f.confidence.toFixed(3)}</td>
                    <td className={tdCls}>{f.anomaly_score.toFixed(3)}{f.is_anomaly && <span className="text-warn ml-1" title="Flagged anomalous">▲</span>}</td>
                    <td className={tdCls}>{f.agreement === "AGREE" ? "agree" : <span className="text-warn">disagree</span>}</td>
                    <td className={tdCls}><ClassTag name={f.final_class} /></td>
                    <td className={`${tdCls} text-text-2`}>{f.evidence_status}</td>
                    <td className={tdCls}><DecisionBadge decision={f.policy_decision} /></td>
                    <td className={tdCls}>{f.defense_action === "BLOCK" ? <span className="text-crit" title="Blocked by an earlier active policy">{f.applied_policy_id}</span> : f.defense_action ? <span className="text-text-3">allow</span> : <span className="text-text-3" title="This input has no source addresses">n/a</span>}</td>
                    <td className={`${tdCls} text-text-3`}>{f.ground_truth_evaluation_only}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </TableWrap>
      ) : <Empty title="No flows streamed in this session">Press Start to replay validation records.</Empty>}
    </Panel>
  );
}
