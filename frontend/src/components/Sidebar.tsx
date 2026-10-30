import { Activity, BarChart3, FlaskConical, Network, Radar, Search, ShieldCheck, type LucideIcon } from "lucide-react";
import { NavLink } from "react-router-dom";

const NAV: { to: string; label: string; icon: LucideIcon }[] = [
  { to: "/command", label: "Command Centre", icon: Radar },
  { to: "/intelligence", label: "Attack Intelligence", icon: Network },
  { to: "/investigate", label: "Investigation Workbench", icon: Search },
  { to: "/models", label: "Model Intelligence", icon: BarChart3 },
  { to: "/defence", label: "Defence & Audit", icon: ShieldCheck },
  { to: "/replay", label: "Replay Lab", icon: FlaskConical },
];

export function Sidebar() {
  return (
    <aside className="md:w-56 shrink-0 border-b md:border-b-0 md:border-r border-ink-700 bg-ink-900 md:flex md:flex-col">
      <div className="hidden md:block px-4 py-4">
        <div className="flex items-center gap-2 font-semibold tracking-tight">
          <Activity size={16} className="text-accent" aria-hidden /> CyberSentinel X
        </div>
        <p className="text-[11px] text-text-3 mt-1">Offline replay. Decisions are simulated.</p>
      </div>
      <nav className="flex md:flex-col gap-0.5 px-2 py-2 overflow-x-auto" aria-label="Primary">
        {NAV.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            title={label}
            className={({ isActive }) =>
              `flex items-center gap-2 rounded-md px-2.5 py-2 whitespace-nowrap transition-colors ${
                isActive ? "bg-accent/10 text-accent" : "text-text-2 hover:bg-ink-800 hover:text-text-1"
              }`
            }
          >
            <Icon size={15} aria-hidden />
            <span className="hidden sm:inline">{label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
