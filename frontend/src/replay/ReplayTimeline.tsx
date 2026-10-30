import { fmt, pct } from "../components/ui";
import type { ReplayStatus } from "../services/types";

export function ReplayTimeline({ status }: { status: ReplayStatus | null }) {
  return (
    <div className="mt-4">
      <div className="flex justify-between text-xs text-text-2 mb-1 num">
        <span className="capitalize">{status?.status ?? "idle"}</span>
        <span>{fmt(status?.cursor)} of {fmt(status?.total)} ({pct(status?.progress, 1)})</span>
      </div>
      <div className="h-2 rounded-full bg-ink-700 overflow-hidden" role="progressbar" aria-valuenow={Math.round((status?.progress ?? 0) * 100)} aria-valuemin={0} aria-valuemax={100} aria-label="Replay progress">
        <div className="h-full bg-accent transition-[width] duration-500" style={{ width: `${(status?.progress ?? 0) * 100}%` }} />
      </div>
    </div>
  );
}
