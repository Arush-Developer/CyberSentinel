import { Empty, Panel, fmt } from "../components/ui";
import type { FlowDetail } from "../services/types";

/** The cross-flow hypothesis this flow belongs to, what supports and contradicts it, and its network context. */
export function HypothesisPanel({ data }: { data: FlowDetail }) {
  return (
    <Panel title="Campaign and network context">
      {data.campaign ? (
        <div className="text-xs space-y-1.5 text-text-2">
          <p className="text-text-1 font-medium">{data.campaign.campaign_id}: {data.campaign.campaign_type} on {data.campaign.target}</p>
          <p>{fmt(data.campaign.flow_count)} flows over {data.campaign.windows_observed} windows, {data.campaign.confidence} confidence.</p>
          <p className="text-text-1">{data.campaign.hypothesis}</p>
          <p>{data.campaign.confidence_basis}</p>
          {data.campaign.contradicting_evidence.map((c) => <p key={c}><span className="text-text-3">Against: </span>{c}</p>)}
          <p className="text-text-3">{data.campaign.uncertainty}</p>
        </div>
      ) : <Empty title="Not part of a campaign hypothesis" />}
      <dl className="mt-3 text-xs grid grid-cols-2 gap-2">
        {Object.entries(data.network).map(([k, v]) => <div key={k}><dt className="text-text-3">{k}</dt><dd className="num">{String(v)}</dd></div>)}
      </dl>
      {data.unavailable_metadata.length > 0 && (
        <p className="mt-3 text-[11px] text-text-3">Absent from this partition: {data.unavailable_metadata.join(", ")}.</p>
      )}
    </Panel>
  );
}
