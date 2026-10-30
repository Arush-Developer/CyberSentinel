import { Page } from "../components/ui";
import { useApi } from "../services/api";
import type { PolicyState } from "../services/types";
import { AdaptiveDefense } from "./AdaptiveDefense";
import { AuditLogs } from "./AuditLogs";
import { DecisionHistory } from "./DecisionHistory";
import { PolicyControls } from "./PolicyControls";

export function DefenceAudit() {
  const policy = useApi<PolicyState>("/policy");
  return (
    <Page title="Defence & Audit" subtitle="Simulated policy only: no firewall or network is changed. Every threshold change and tool call is logged.">
      <AdaptiveDefense />
      <PolicyControls policy={policy.data} onApplied={policy.reload} />
      <DecisionHistory history={policy.data?.history ?? []} />
      <AuditLogs />
    </Page>
  );
}
