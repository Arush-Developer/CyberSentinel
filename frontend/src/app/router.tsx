import { Navigate, Route, Routes } from "react-router-dom";
import { ModelMetrics } from "../analytics/ModelMetrics";
import { ThreatAnalytics } from "../analytics/ThreatAnalytics";
import { DefenceAudit } from "../audit/DefenceAudit";
import { InvestigationWorkbench } from "../investigations/InvestigationWorkbench";
import { CommandCenter } from "../pages/CommandCenter";
import { ReplayLab } from "../replay/ReplayLab";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/command" replace />} />
      <Route path="/command" element={<CommandCenter />} />
      <Route path="/intelligence" element={<ThreatAnalytics />} />
      <Route path="/investigate" element={<InvestigationWorkbench />} />
      <Route path="/models" element={<ModelMetrics />} />
      <Route path="/defence" element={<DefenceAudit />} />
      <Route path="/replay" element={<ReplayLab />} />
      <Route path="*" element={<Navigate to="/command" replace />} />
    </Routes>
  );
}
