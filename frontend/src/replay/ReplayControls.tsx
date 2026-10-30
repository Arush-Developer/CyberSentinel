import { OctagonX, Pause, Play, RotateCcw, StepForward } from "lucide-react";
import { useState } from "react";
import { Btn, fmt } from "../components/ui";
import type { ReplayStatus } from "../services/types";

const SPEEDS = [50, 200, 500, 2000, 10000, 50000];

export function ReplayControls({ status, connected, call }: {
  status: ReplayStatus | null;
  connected: boolean;
  call: (path: string, body?: unknown) => void;
}) {
  const [speed, setSpeed] = useState(500);
  const [limit, setLimit] = useState("");
  const s = status?.status ?? "idle";
  const running = s === "running";
  const paused = s === "paused";
  const canResumeSaved = s === "stopped" && (status?.cursor ?? 0) > 0;
  const start = (resume: boolean) =>
    call("/replay/start", { speed, batch_size: 500, limit: limit ? Number(limit) : null, resume_saved: resume });

  return (
    <div className="flex flex-wrap items-end gap-3">
      <div className="flex flex-wrap gap-2">
        <Btn tone="primary" onClick={() => start(false)} disabled={running || paused}><Play size={14} aria-hidden /> Start</Btn>
        <Btn onClick={() => call("/replay/pause")} disabled={!running}><Pause size={14} aria-hidden /> Pause</Btn>
        <Btn onClick={() => call("/replay/resume")} disabled={!paused}><StepForward size={14} aria-hidden /> Resume</Btn>
        <Btn tone="danger" onClick={() => call("/replay/stop")} disabled={!running && !paused}><OctagonX size={14} aria-hidden /> Stop</Btn>
        <Btn onClick={() => start(true)} disabled={!canResumeSaved} title="Continue from the last saved position"><RotateCcw size={14} aria-hidden /> Continue saved</Btn>
      </div>
      <label className="text-xs text-text-2">
        Speed (flows/s)
        <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))} disabled={running || paused} className="block mt-1 bg-ink-800 border border-ink-600 rounded-md px-2 py-1.5 text-text-1">
          {SPEEDS.map((v) => <option key={v} value={v}>{v.toLocaleString("en-IN")}</option>)}
        </select>
      </label>
      <label className="text-xs text-text-2">
        Flow limit (optional)
        <input type="number" min={1} value={limit} onChange={(e) => setLimit(e.target.value)} disabled={running || paused} placeholder={fmt(status?.total)} className="block mt-1 w-28 bg-ink-800 border border-ink-600 rounded-md px-2 py-1.5 text-text-1 num" />
      </label>
      <div className="ml-auto text-xs text-text-3 flex items-center gap-2">
        <span className={`w-2 h-2 rounded-full ${connected ? "bg-good" : "bg-ink-600"}`} aria-hidden />
        {connected ? "Event stream connected" : "Event stream disconnected"}
      </div>
    </div>
  );
}
