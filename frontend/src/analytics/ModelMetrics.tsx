import { BarList, CLASS_COLOR, Notice, Page, Panel, Stat, TableWrap, fmt, pct, tdCls, thCls } from "../components/ui";
import { useApi } from "../services/api";
import { CLASSES } from "../services/types";
import { AnomalyAnalytics, type Agent2Report } from "./AnomalyAnalytics";
import { ConfusionMatrix, type ConfusionData } from "./ConfusionMatrix";

interface ClassReport {
  rows: number; accuracy: number; macro_f1: number; balanced_accuracy: number;
  binary_attack_false_positive_rate: number; binary_attack_false_negative_rate: number;
  per_class: Record<string, { precision: number; recall: number; f1: number; support: number; false_positive_rate: number; false_negative_rate: number }>;
  confusion_matrix: ConfusionData;
}
interface PolicyOutcome { counts: Record<string, number>; attacks_blocked_rate: number; attacks_allowed_rate: number; attacks_reviewed_rate: number; benign_allowed_rate: number; benign_blocked_rate: number; benign_reviewed_rate: number }
interface Metrics {
  evaluation_report: {
    model_version: string; anomaly_detector: string; agent_agreement_rate: number;
    agent1: ClassReport; system: ClassReport;
    agent1_excluding_rows_also_in_training: ClassReport & { excluded_rows: number };
    agent2: Agent2Report;
    ablation: Record<string, { macro_f1: number; accuracy: number; policy: PolicyOutcome } | string>;
    investigation: { triggered: number; investigated: number; verdicts: Record<string, number> };
    latency: Record<string, number>;
  } | null;
  training_report: {
    model_comparison_selection_split: Record<string, { macro_f1: number; accuracy: number; balanced_accuracy: number; fit_seconds: number; inference_ms_per_1k_flows: number }>;
    selected_model: string; feature_importance: { feature: string; importance: number }[];
    record_order_validation: ClassReport;
    destination_port_study: { with_port_macro_f1: number; without_port: { macro_f1: number }; use_port: boolean };
    calibration_study: { raw: { ece_15_bins: number }; temperature_scaled: { ece_15_bins: number }; chosen_temperature: number };
  } | null;
  leakage_audit: { cumulative_top_feature_knockout: { removed: number; macro_f1: number }[] } | null;
  dataset: Record<string, { rows: number; label_distribution: Record<string, number> }> | null;
}

const LAYER_NAMES: Record<string, string> = {
  agent1_alone: "Agent 1 alone", agent1_plus_agent2: "+ Agent 2 anomaly", plus_campaign_intelligence: "+ Campaign intelligence", plus_investigation: "+ Investigation",
};

export function ModelMetrics() {
  const { data, error } = useApi<Metrics>("/metrics");
  if (error) return <Page title="Model Intelligence"><Notice tone="crit" title="Could not load metrics">{error}</Notice></Page>;
  if (!data) return <Page title="Model Intelligence"><p className="text-text-3">Loading…</p></Page>;
  const ev = data.evaluation_report;
  const tr = data.training_report;
  if (!ev || !tr) return <Page title="Model Intelligence"><Notice title="Reports not generated yet">Run scripts/train_models.py, scripts/calibrate_fusion.py and scripts/evaluate.py.</Notice></Page>;
  const sys = ev.system;

  const dist = data.dataset?.eval.label_distribution ?? {};

  return (
    <Page title="Model Intelligence" subtitle={`Measured on ${fmt(sys.rows)} official validation records, which were not used for tuning. Model: ${ev.model_version}.`}>
      <Notice title="Near-perfect scores describe this capture, not networks in general">
        <p>Each attack class in this dataset comes from tools with almost constant TCP fingerprints. Removing the 25 strongest features still left macro-F1 at {data.leakage_audit ? data.leakage_audit.cumulative_top_feature_knockout.at(-1)!.macro_f1.toFixed(4) : "–"}, so no single feature is leaking the label.</p>
        <p>Fitting on early records and testing on late ones lowered macro-F1 to {tr.record_order_validation.macro_f1.toFixed(4)}, with DOS recall at {tr.record_order_validation.per_class.DOS.recall.toFixed(4)}. Expect lower scores on traffic from elsewhere.</p>
      </Notice>
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <Stat label="Accuracy" value={sys.accuracy.toFixed(5)} />
        <Stat label="Macro-F1" value={sys.macro_f1.toFixed(5)} hint={`${ev.agent1_excluding_rows_also_in_training.macro_f1.toFixed(5)} without ${fmt(ev.agent1_excluding_rows_also_in_training.excluded_rows)} rows also in training`} />
        <Stat label="Balanced accuracy" value={sys.balanced_accuracy.toFixed(5)} />
        <Stat label="False-positive rate" value={pct(sys.binary_attack_false_positive_rate, 4)} hint="Benign called attack" />
        <Stat label="False-negative rate" value={pct(sys.binary_attack_false_negative_rate, 4)} hint="Attack called benign" />
      </div>
      <div className="grid lg:grid-cols-2 gap-3">
        <Panel title="Per-class performance">
          <TableWrap>
            <table className="w-full num">
              <thead><tr>{["Class", "Precision", "Recall", "F1", "FPR", "FNR", "Support"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
              <tbody>
                {CLASSES.map((c) => {
                  const r = sys.per_class[c];
                  return (
                    <tr key={c}>
                      <td className={tdCls}>{c}</td>
                      <td className={tdCls}>{r.precision.toFixed(4)}</td>
                      <td className={tdCls}>{r.recall.toFixed(4)}</td>
                      <td className={tdCls}>{r.f1.toFixed(4)}</td>
                      <td className={tdCls}>{r.false_positive_rate.toFixed(5)}</td>
                      <td className={tdCls}>{r.false_negative_rate.toFixed(5)}</td>
                      <td className={tdCls}>{fmt(r.support)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        </Panel>
        <Panel title="Confusion matrix" hint="Outlined cells are errors. Shading is logarithmic.">
          <ConfusionMatrix matrix={sys.confusion_matrix} />
        </Panel>
      </div>
      <div className="grid lg:grid-cols-2 gap-3">
        <Panel title="Model comparison" hint="Internal selection split, not the validation records">
          <TableWrap>
            <table className="w-full num">
              <thead><tr>{["Model", "Macro-F1", "Accuracy", "Fit s", "ms / 1k flows"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
              <tbody>
                {Object.entries(tr.model_comparison_selection_split).sort((a, b) => b[1].macro_f1 - a[1].macro_f1).map(([name, m]) => (
                  <tr key={name}>
                    <td className={tdCls}>{name}{name === tr.selected_model && <span className="text-accent ml-1.5 text-[11px]">selected</span>}</td>
                    <td className={tdCls}>{m.macro_f1.toFixed(5)}</td>
                    <td className={tdCls}>{m.accuracy.toFixed(5)}</td>
                    <td className={tdCls}>{m.fit_seconds}</td>
                    <td className={tdCls}>{m.inference_ms_per_1k_flows}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <p className="text-xs text-text-3 mt-3">
            Destination Port: macro-F1 {tr.destination_port_study.with_port_macro_f1.toFixed(5)} with it, {tr.destination_port_study.without_port.macro_f1.toFixed(5)} without. {tr.destination_port_study.use_port ? "Kept." : "Dropped because it added nothing."}{" "}
            Calibration error (ECE) {tr.calibration_study.raw.ece_15_bins.toFixed(5)} raw, {tr.calibration_study.temperature_scaled.ece_15_bins.toFixed(5)} at temperature {tr.calibration_study.chosen_temperature}.
          </p>
        </Panel>
        <Panel title="Feature importance" hint={`Top 12 from ${tr.selected_model}`}>
          <BarList items={tr.feature_importance.slice(0, 12).map((f) => ({ label: f.feature, value: +f.importance.toFixed(2) }))} />
        </Panel>
      </div>
      <AnomalyAnalytics report={ev.agent2} detector={ev.anomaly_detector} />
      <Panel title="Ablation: what each layer changes" hint="Classification does not move, because final_class stays with Agent 1. The layers change how decisions are routed, at the cost of more review.">
        <TableWrap>
          <table className="w-full num">
            <thead><tr>{["Layers", "Macro-F1", "Attacks blocked", "Attacks auto-allowed", "Benign auto-allowed", "Benign blocked", "Benign sent to review"].map((h) => <th key={h} className={thCls}>{h}</th>)}</tr></thead>
            <tbody>
              {Object.entries(ev.ablation).flatMap(([name, layer]) => typeof layer === "string" ? [] : [(
                <tr key={name}>
                  <td className={tdCls}>{LAYER_NAMES[name] ?? name}</td>
                  <td className={tdCls}>{layer.macro_f1.toFixed(5)}</td>
                  <td className={tdCls}>{pct(layer.policy.attacks_blocked_rate)}</td>
                  <td className={tdCls}>{pct(layer.policy.attacks_allowed_rate, 4)}</td>
                  <td className={tdCls}>{pct(layer.policy.benign_allowed_rate)}</td>
                  <td className={tdCls}>{pct(layer.policy.benign_blocked_rate, 4)}</td>
                  <td className={tdCls}>{pct(layer.policy.benign_reviewed_rate)}</td>
                </tr>
              )])}
            </tbody>
          </table>
        </TableWrap>
      </Panel>
      <div className="grid lg:grid-cols-2 gap-3">
        <Panel title="Validation class distribution">
          <BarList items={CLASSES.map((c) => ({ label: c, value: dist[c] ?? 0, color: CLASS_COLOR[c] }))} />
        </Panel>
        <Panel title="Operations">
          <dl className="grid grid-cols-2 gap-3 text-xs">
            <div><dt className="text-text-3">Agent agreement</dt><dd className="num text-base">{pct(ev.agent_agreement_rate, 1)}</dd></div>
            <div><dt className="text-text-3">Investigation triggers</dt><dd className="num text-base">{fmt(ev.investigation.triggered)}</dd></div>
            <div><dt className="text-text-3">Agent 1 latency</dt><dd className="num text-base">{ev.latency.agent1_ms_per_1k_flows.toFixed(2)} ms / 1k</dd></div>
            <div><dt className="text-text-3">Agent 2 latency</dt><dd className="num text-base">{ev.latency.agent2_ms_per_1k_flows.toFixed(2)} ms / 1k</dd></div>
            <div><dt className="text-text-3">Pipeline throughput</dt><dd className="num text-base">{fmt(Math.round(ev.latency.scoring_campaign_fusion_policy_flows_per_second))} flows/s</dd></div>
            <div><dt className="text-text-3">Investigation verdicts</dt><dd className="text-text-2">{Object.entries(ev.investigation.verdicts).map(([k, v]) => `${k}: ${fmt(v)}`).join(", ")}</dd></div>
          </dl>
        </Panel>
      </div>
    </Page>
  );
}
