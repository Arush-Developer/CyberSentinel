import type { ReactNode } from "react";
import { useApi } from "../services/api";
import { Navbar } from "./Navbar";
import { Sidebar } from "./Sidebar";
import { Notice } from "./ui";

/** App shell. Screens render only once the backend reports its models are loaded. */
export function Layout({ children }: { children: ReactNode }) {
  const health = useApi<{ status: string; detail: string | null }>("/health", 3000);
  const ready = health.data?.status === "ok";
  return (
    <div className="h-full md:flex">
      <Sidebar />
      <div className="flex-1 min-w-0 h-full flex flex-col">
        <Navbar ready={ready} />
        <main className="flex-1 min-h-0 overflow-y-auto">
          {health.error && (
            <div className="p-4"><Notice tone="crit" title="Backend unreachable">{health.error}. Start it with uvicorn on port 8000.</Notice></div>
          )}
          {health.data?.status === "unavailable" && (
            <div className="p-4"><Notice tone="crit" title="Backend could not load models">{health.data.detail}</Notice></div>
          )}
          {health.data?.status === "loading" && (
            <div className="p-4"><Notice tone="info" title="Backend is loading models and scoring the validation records…" /></div>
          )}
          {ready && children}
        </main>
      </div>
    </div>
  );
}
