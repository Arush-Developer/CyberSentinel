import { useState } from "react";
import { Link } from "react-router-dom";
import { BarList, CLASS_COLOR, Empty, Notice, Page, Panel, Stat, Tag, fmt } from "../components/ui";
import { post, useApi } from "../services/api";
import { useReplayStream } from "../services/replay";
import { CLASSES, type ReplayStatus } from "../services/types";
import { LiveFlowFeed } from "./LiveFlowFeed";
import { ReplayControls } from "./ReplayControls";
import { ReplayTimeline } from "./ReplayTimeline";

export function ReplayLab() {
  const { data: status, error, reload } = useApi<ReplayStatus>("/replay/status", 700);
  const stream = useReplayStream();
  const [problem, setProblem] = useState<string | null>(null);

  const call = async (path: string, body?: unknown) => {
    setProblem(null);
    try {
      await post(path, body);
      reload();
    } catch (e) {
      setProblem((e as Error).message);
    }
  };

  return (
    <Page title="Replay Lab" subtitle="Streams the real validation records through the full pipeline in record order. No traffic is generated and nothing touches a network.">
      {(error || problem) && <Notice tone="crit" title="Replay request failed">{problem ?? error}</Notice>}
      {status?.campaign_mode === "cohort" && (
        <Notice tone="info" title="Record order stands in for time">The pack has no timestamps or sequence numbers, so flows replay in record_id order. This is not verified chronology.</Notice>
      )}
      <Panel>
        <ReplayControls status={status} connected={stream.connected} call={call} />
        <ReplayTimeline status={status} />
      </Panel>
      {status && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <Stat label="Pipeline throughput" value={status.inference_flows_per_second ? fmt(status.inference_flows_per_second) : "–"} hint="Flows/s of scoring, before release pacing" />
          <Stat label="Campaign hypotheses" value={fmt(status.campaigns)} hint={`${status.campaign_mode} mode`} />
          <Stat label="Investigation triggers" value={fmt(status.investigation_triggers)} hint={`${fmt(status.investigations)} investigated (budget 5 per batch)`} />
          <Stat label="Decisions" value={<span className="text-base">{fmt(status.counts.decisions.ALLOW)} / {fmt(status.counts.decisions.BLOCK)} / {fmt(status.counts.decisions.REVIEW)}</span>} hint="Allow / block / review" />
        </div>
      )}
      <div className="grid xl:grid-cols-[1fr_340px] gap-3 items-start">
        <LiveFlowFeed flows={stream.flows} />
        <div className="space-y-3">
          <Panel title="Final class so far">
            <BarList total={Math.max(status?.counts.total ?? 0, 1)} items={CLASSES.map((c) => ({ label: c, value: status?.counts.classes[c] ?? 0, color: CLASS_COLOR[c] }))} />
          </Panel>
          <Panel title="Campaign detections">
            {stream.campaigns.length ? (
              <ul className="space-y-2 max-h-52 overflow-y-auto text-xs">
                {stream.campaigns.map((c) => (
                  <li key={c.seq}>
                    <Tag tone={c.action === "detected" ? "crit" : "neutral"}>{c.action}</Tag>{" "}
                    <span className="font-medium">{c.campaign.campaign_id}</span> {c.campaign.campaign_type} on {c.campaign.target}
                    <span className="text-text-3 num"> ({fmt(c.campaign.flow_count)} flows)</span>
                  </li>
                ))}
              </ul>
            ) : <Empty title="None yet" />}
          </Panel>
          <Panel title="Investigations">
            {stream.investigations.length ? (
              <ul className="space-y-2 max-h-52 overflow-y-auto text-xs">
                {stream.investigations.map((i) => (
                  <li key={i.seq}>
                    <Link className="text-accent num hover:underline" to={`/investigate?flow=${i.flow_id}`}>{i.flow_id}</Link>{" "}
                    <Tag tone={i.verdict === "CONFLICTING" ? "warn" : "neutral"}>{i.verdict}</Tag>
                    <p className="text-text-3 mt-0.5">{i.tools.join(", ")}</p>
                  </li>
                ))}
              </ul>
            ) : <Empty title="None yet" />}
          </Panel>
        </div>
      </div>
    </Page>
  );
}
