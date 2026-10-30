import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { BarList, CLASS_COLOR, Panel, pct } from "../components/ui";
import { CLASSES } from "../services/types";

export interface Agent2Report {
  roc_auc: number; pr_auc: number; recall: number; false_positive_rate: number; precision: number;
  per_class_flag_rate: Record<string, number>;
  threshold_curve: { threshold: number; recall: number; false_positive_rate: number }[];
  score_histogram_by_class: Record<string, number[]>;
}

const axis = { tick: { fill: "#a9b5c7", fontSize: 11 }, axisLine: { stroke: "#33445f" }, tickLine: false };
const tooltip = { contentStyle: { background: "#0e1524", border: "1px solid #33445f", borderRadius: 6, fontSize: 12 } };

export function AnomalyAnalytics({ report, detector }: { report: Agent2Report; detector: string }) {
  const buckets = report.score_histogram_by_class.BENIGN.map((_, i) => {
    const benign = report.score_histogram_by_class.BENIGN[i];
    const attack = CLASSES.filter((c) => c !== "BENIGN").reduce((sum, c) => sum + report.score_histogram_by_class[c][i], 0);
    return { bin: (i / 20).toFixed(2), Benign: benign, Attack: attack };
  });
  return (
    <div className="grid lg:grid-cols-2 gap-3">
        <Panel title={`Agent 2 score distribution (${detector})`} hint={`ROC-AUC ${report.roc_auc.toFixed(3)}, PR-AUC ${report.pr_auc.toFixed(3)}. Flows per score bin, log scale.`}>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={buckets} barGap={0} margin={{ top: 6, right: 8, bottom: 0, left: 0 }}>
                <CartesianGrid vertical={false} stroke="#22304a" />
                <XAxis dataKey="bin" {...axis} interval={3} />
                <YAxis {...axis} scale="log" domain={[1, "auto"]} allowDataOverflow width={52} tickFormatter={(v: number) => v.toLocaleString("en-IN")} />
                <Tooltip {...tooltip} cursor={{ fill: "#172236" }} formatter={(v: number) => v.toLocaleString("en-IN")} />
                <Bar dataKey="Benign" fill="#3987e5" radius={[2, 2, 0, 0]} />
                <Bar dataKey="Attack" fill="#d95926" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="flex gap-4 text-xs text-text-2 mt-1">
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm bg-[#3987e5]" />Benign</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm bg-[#d95926]" />Attack</span>
          </div>
        </Panel>
        <Panel title="Agent 2 flag rate by true class" hint={`At threshold 0.95: recall ${pct(report.recall, 1)}, false-positive rate ${pct(report.false_positive_rate, 1)}. Brute force and port scans mostly look statistically normal to it.`}>
          <BarList total={1} items={CLASSES.map((c) => ({ label: c, value: +report.per_class_flag_rate[c].toFixed(4), color: CLASS_COLOR[c] }))} />
          <div className="h-32 mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={report.threshold_curve} margin={{ top: 6, right: 8, bottom: 0, left: 0 }}>
                <CartesianGrid vertical={false} stroke="#22304a" />
                <XAxis dataKey="threshold" {...axis} />
                <YAxis {...axis} domain={[0, 1]} width={32} />
                <Tooltip {...tooltip} formatter={(v: number) => v.toFixed(3)} />
                <Line dataKey="recall" name="Recall" stroke="#38bdf8" strokeWidth={2} dot={{ r: 3 }} />
                <Line dataKey="false_positive_rate" name="False-positive rate" stroke="#fbbf24" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="flex gap-4 text-xs text-text-2 mt-1">
            <span className="flex items-center gap-1.5"><span className="w-2 h-0.5 bg-accent" />Recall</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-0.5 bg-warn" />False-positive rate</span>
          </div>
        </Panel>
    </div>
  );
}
