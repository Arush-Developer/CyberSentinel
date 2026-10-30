import { OctagonX } from "lucide-react";
import { useState } from "react";
import { post, useApi } from "../services/api";
import type { ReplayStatus } from "../services/types";
import { Btn } from "./ui";

/** Replay state and the global stop, visible from every screen. */
export function Navbar({ ready }: { ready: boolean }) {
  const replay = useApi<ReplayStatus>(ready ? "/replay/status" : null, 2000);
  const [stopping, setStopping] = useState(false);
  const status = replay.data?.status ?? "idle";
  const active = status === "running" || status === "paused";

  const stop = async () => {
    setStopping(true);
    try {
      await post("/replay/stop");
      replay.reload();
    } finally {
      setStopping(false);
    }
  };

  return (
    <header className="shrink-0 flex items-center justify-end gap-3 border-b border-ink-700 bg-ink-900 px-4 py-2">
      <span className="text-xs text-text-3">
        Replay <span className={`capitalize ${active ? "text-accent" : "text-text-2"}`}>{status}</span>
      </span>
      <Btn tone="danger" onClick={stop} disabled={!active || stopping} title="Stop replay and running investigations">
        <OctagonX size={14} aria-hidden /> STOP
      </Btn>
    </header>
  );
}
