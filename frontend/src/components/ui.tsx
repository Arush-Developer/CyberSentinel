import { AlertTriangle, CheckCircle2, CircleHelp, ShieldX, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import type { Decision } from "../services/types";

// Fixed class colours, validated against the panel surface for colour-vision deficiency.
export const CLASS_COLOR: Record<string, string> = {
  BENIGN: "#3987e5",
  BRUTE_FORCE: "#199e70",
  DOS: "#c98500",
  DDOS: "#d55181",
  PORT_SCAN: "#9085e9",
};

export const fmt = (n: number | null | undefined) => (n == null ? "–" : n.toLocaleString("en-IN"));
export const pct = (n: number | null | undefined, digits = 2) => (n == null ? "–" : `${(n * 100).toFixed(digits)}%`);

export function Page({ title, subtitle, actions, children }: { title: string; subtitle?: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <div className="p-4 md:p-6 space-y-4 max-w-[1500px] mx-auto">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {subtitle && <p className="text-text-2 mt-0.5 max-w-3xl">{subtitle}</p>}
        </div>
        {actions}
      </header>
      {children}
    </div>
  );
}

export function Panel({ title, hint, actions, children, className = "" }: { title?: string; hint?: string; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-ink-700 bg-ink-850 p-4 min-w-0 ${className}`}>
      {(title || actions) && (
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="min-w-0">
            {title && <h2 className="font-medium text-text-1">{title}</h2>}
            {hint && <p className="text-xs text-text-3 mt-0.5">{hint}</p>}
          </div>
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, hint, accent }: { label: string; value: ReactNode; hint?: string; accent?: string }) {
  return (
    <div className="rounded-lg border border-ink-700 bg-ink-850 px-4 py-3 min-w-0">
      <div className="flex items-center gap-1.5 text-xs text-text-2">
        {accent && <span className="inline-block w-2 h-2 rounded-full shrink-0" style={{ background: accent }} />}
        <span className="truncate">{label}</span>
      </div>
      <div className="text-2xl font-semibold num mt-1 tracking-tight">{value}</div>
      {hint && <div className="text-xs text-text-3 mt-0.5">{hint}</div>}
    </div>
  );
}

const DECISION_STYLE: Record<Decision, { icon: LucideIcon; cls: string }> = {
  ALLOW: { icon: CheckCircle2, cls: "text-good border-good/30 bg-good/10" },
  BLOCK: { icon: ShieldX, cls: "text-crit border-crit/30 bg-crit/10" },
  REVIEW: { icon: CircleHelp, cls: "text-warn border-warn/30 bg-warn/10" },
};

export function DecisionBadge({ decision }: { decision: Decision }) {
  const { icon: Icon, cls } = DECISION_STYLE[decision];
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium ${cls}`}>
      <Icon size={12} aria-hidden /> {decision}
    </span>
  );
}

export function ClassTag({ name }: { name: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span className="w-2 h-2 rounded-sm shrink-0" style={{ background: CLASS_COLOR[name] ?? "#74829a" }} />
      <span className="text-text-1">{name}</span>
    </span>
  );
}

export function Tag({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "accent" | "warn" | "crit" | "good" }) {
  const tones = {
    neutral: "text-text-2 border-ink-600 bg-ink-800",
    accent: "text-accent border-accent/30 bg-accent/10",
    warn: "text-warn border-warn/30 bg-warn/10",
    crit: "text-crit border-crit/30 bg-crit/10",
    good: "text-good border-good/30 bg-good/10",
  };
  return <span className={`inline-block rounded border px-1.5 py-0.5 text-[11px] ${tones[tone]}`}>{children}</span>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-md border border-dashed border-ink-600 p-6 text-center">
      <p className="font-medium text-text-2">{title}</p>
      {children && <div className="text-xs text-text-3 mt-1">{children}</div>}
    </div>
  );
}

export function Notice({ tone = "warn", title, children }: { tone?: "warn" | "crit" | "info"; title: string; children?: ReactNode }) {
  const cls = { warn: "border-warn/30 bg-warn/5 text-warn", crit: "border-crit/30 bg-crit/5 text-crit", info: "border-accent/30 bg-accent/5 text-accent" }[tone];
  return (
    <div className={`flex gap-2 rounded-lg border p-3 ${cls}`} role={tone === "crit" ? "alert" : "status"}>
      <AlertTriangle size={15} className="shrink-0 mt-0.5" aria-hidden />
      <div className="min-w-0">
        <p className="font-medium">{title}</p>
        {children && <div className="text-text-2 mt-1 text-xs space-y-0.5">{children}</div>}
      </div>
    </div>
  );
}

export function Btn({ tone = "default", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { tone?: "default" | "primary" | "danger" }) {
  const tones = {
    default: "border-ink-600 bg-ink-800 text-text-1 hover:bg-ink-700",
    primary: "border-accent/50 bg-accent/15 text-accent hover:bg-accent/25",
    danger: "border-crit/50 bg-crit/15 text-crit hover:bg-crit/25",
  };
  return (
    <button
      {...props}
      className={`inline-flex items-center justify-center gap-1.5 rounded-md border px-3 py-1.5 font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${tones[tone]} ${props.className ?? ""}`}
    />
  );
}

/** Proportional rows with a text value beside every bar, so nothing relies on colour. */
export function BarList({ items, total }: { items: { label: ReactNode; value: number; color?: string }[]; total?: number }) {
  const max = total ?? Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="space-y-2">
      {items.map((item, i) => (
        <div key={i} className="grid grid-cols-[minmax(90px,150px)_1fr_64px] items-center gap-2">
          <div className="truncate text-xs text-text-2" title={typeof item.label === "string" ? item.label : undefined}>{item.label}</div>
          <div className="h-1.5 rounded-full bg-ink-700 overflow-hidden">
            <div className="h-full rounded-full transition-[width] duration-300" style={{ width: `${(item.value / max) * 100}%`, background: item.color ?? "#38bdf8" }} />
          </div>
          <div className="text-right num text-xs text-text-1">{fmt(item.value)}</div>
        </div>
      ))}
    </div>
  );
}

export function TableWrap({ children }: { children: ReactNode }) {
  return <div className="overflow-x-auto -mx-4 px-4">{children}</div>;
}

export const thCls = "text-left text-[11px] uppercase tracking-wide text-text-3 pb-2 pr-3 whitespace-nowrap";
export const tdCls = "py-1.5 pr-3 border-t border-ink-700/70 whitespace-nowrap";
