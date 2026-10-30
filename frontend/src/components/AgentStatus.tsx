import { useApi } from "../services/api";
import type { ModelStatus } from "../services/types";
import { Panel } from "./ui";

/** What is actually loaded behind each agent, as reported by the backend. */
export function AgentStatus() {
  const { data } = useApi<ModelStatus>("/models/status");
  if (!data) return null;
  const agents = [
    { name: "Agent 1: threat detection", value: data.threat_model, detail: `${data.threat_features} features` },
    { name: "Agent 2: anomaly detection", value: data.anomaly_detector, detail: `Flags at percentile ${data.anomaly_threshold}, ${data.anomaly_features} features` },
    { name: "Agent 3: evidence fusion", value: "Deterministic rules", detail: "Keeps class, evidence status and policy separate" },
    { name: "Agent 4: temporal correlation", value: data.defense_available ? "On" : "Off", detail: data.defense_available ? "Sliding window over observed endpoints" : "Needs source_ip; the participant pack has none" },
    { name: "Agent 5: adaptive defence", value: data.defense_available ? "On" : "Off", detail: data.defense_available ? "Temporary simulated SOURCE_IP policies" : "Needs source_ip; the participant pack has none" },
    { name: "Campaign engine", value: `${data.campaign_mode} mode`, detail: data.campaign_mode === "endpoint" ? "Endpoint metadata available" : "No endpoint metadata in this partition" },
    { name: "Investigation", value: "Deterministic planner", detail: data.llm_in_use ? "LLM in use" : "No LLM in use" },
  ];
  return (
    <Panel title="Agents">
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-4">
        {agents.map((agent) => (
          <div key={agent.name} className="min-w-0">
            <p className="text-xs text-text-3">{agent.name}</p>
            <p className="font-medium truncate" title={agent.value}>{agent.value}</p>
            <p className="text-xs text-text-2">{agent.detail}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}
