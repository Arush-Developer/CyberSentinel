import { Link } from "react-router-dom";
import { AgentStatus } from "../components/AgentStatus";
import { BarList, CLASS_COLOR, ClassTag, DecisionBadge, Empty, Notice, Page, Panel, Stat, fmt, pct } from "../components/ui";
import { IncidentTimeline } from "../investigations/IncidentTimeline";
import { useApi } from "../services/api";
import { CLASSES, type Incident, type ReplayStatus } from "../services/types";

interface Summary {
  replay: ReplayStatus;
  incidents: { scope: string; total: number; items: Incident[] };
  campaign_mode: string;
  limitations: string[];
}

export function CommandCenter() {
  const { data, error } = useApi<Summary>("/summary", 1500);
  if (error && !data) return <Page title="Command Centre"><Notice tone="crit" title="Could not load summary">{error}</Notice></Page>;
  if (!data) return <Page title="Command Centre"><p className="text-text-3">Loading…</p></Page>;
  const { replay, incidents } = data;
  const c = replay.counts;
  const agree = c.agreement.AGREE ?? 0;
  const disagree = c.agreement.DISAGREE ?? 0;

  return (
    <Page title="Command Centre" subtitle="Live totals from the current replay of the official validation records. Decisions are simulated.">
      {replay.cursor === 0 && (
        <Notice tone="info" title="No replay has run yet">
          Counts stay at zero until flows are replayed. <Link className="underline text-accent" to="/replay">Open Replay Lab</Link> to start one.
        </Notice>
      )}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="Replayed flows" value={fmt(c.total)} hint={`of ${fmt(replay.total)} (${pct(replay.progress, 1)})`} />
        <Stat label="Replay state" value={<span className="text-lg capitalize">{replay.status}</span>} hint={replay.inference_flows_per_second ? `${fmt(replay.inference_flows_per_second)} flows/s pipeline throughput` : undefined} />
        <Stat label="Agents agree" value={c.total ? pct(agree / c.total, 1) : "–"} hint={`${fmt(agree)} agree, ${fmt(disagree)} disagree`} />
        <Stat label="Campaign hypotheses" value={fmt(replay.campaigns)} hint={`${fmt(replay.investigations)} investigations, ${fmt(replay.investigation_triggers)} triggers`} />
      </div>
      <AgentStatus />
      <div className={`grid gap-3 ${replay.defense_available ? "lg:grid-cols-4" : "lg:grid-cols-3"}`}>
        <Panel title="Final class">
          <BarList items={CLASSES.map((name) => ({ label: name, value: c.classes[name] ?? 0, color: CLASS_COLOR[name] }))} total={Math.max(c.total, 1)} />
        </Panel>
        <Panel title="Simulated policy decisions">
          <div className="space-y-3">
            {(["ALLOW", "BLOCK", "REVIEW"] as const).map((d) => (
              <div key={d} className="flex items-center justify-between">
                <DecisionBadge decision={d} />
                <span className="num text-lg font-medium">{fmt(c.decisions[d] ?? 0)}</span>
              </div>
            ))}
          </div>
        </Panel>
        {replay.defense_available && (
          <Panel title="Agent 5 actions" hint="Replay actions from active policies">
            <div className="space-y-3">
              {(["ALLOW", "BLOCK"] as const).map((d) => (
                <div key={d} className="flex items-center justify-between">
                  <DecisionBadge decision={d} />
                  <span className="num text-lg font-medium">{fmt(c.defense[d] ?? 0)}</span>
                </div>
              ))}
              <p className="text-xs text-text-3">{fmt(replay.policies_activated)} policies activated, {fmt(replay.active_policies)} active, {fmt(replay.correlation_groups)} Agent 4 groups.</p>
            </div>
          </Panel>
        )}
        <Panel title="Evidence status">
          {Object.keys(c.evidence).length ? (
            <BarList items={Object.entries(c.evidence).sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }))} total={Math.max(c.total, 1)} />
          ) : <Empty title="No flows replayed" />}
        </Panel>
      </div>
      <IncidentTimeline incidents={incidents.items} total={incidents.total} scope={incidents.scope} />
      {data.campaign_mode !== "endpoint" && (
        <Panel title="Data limits on this partition">
          <ul className="list-disc ml-4 text-text-2 space-y-1 text-xs">{data.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
        </Panel>
      )}
      <p className="text-[11px] text-text-3"><ClassTag name="BENIGN" /> colours are fixed per class across every screen.</p>
    </Page>
  );
}
