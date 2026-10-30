// Thin client for the FastAPI backend. Every number on screen comes through here.
import { useEffect, useState } from "react";

export class ApiError extends Error {}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* Keep the status text. */
    }
    throw new ApiError(detail);
  }
  return response.json();
}

export const post = <T,>(path: string, body?: unknown) =>
  api<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

/** Fetches once (or on an interval). Errors surface to the caller; stale data stays visible. */
export function useApi<T>(path: string | null, intervalMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!path) return;
    let live = true;
    const load = () =>
      api<T>(path)
        .then((d) => { if (live) { setData(d); setError(null); } })
        .catch((e: Error) => { if (live) setError(e.message); });
    load();
    const timer = intervalMs ? setInterval(load, intervalMs) : undefined;
    return () => { live = false; if (timer) clearInterval(timer); };
  }, [path, intervalMs, tick]);
  return { data, error, reload: () => setTick((t) => t + 1) };
}
