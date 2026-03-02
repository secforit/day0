import { ShieldAlert, AlertCircle, AlertTriangle, ShieldCheck, Activity } from "lucide-react"

interface StatsRowProps {
  total: number
  kev: number
  critical: number
  high: number
  medium: number
}

const stats = [
  { key: "total", label: "Total CVEs", icon: Activity, colorClass: "text-foreground" },
  { key: "kev", label: "KEV Entries", icon: ShieldAlert, colorClass: "text-severity-critical" },
  { key: "critical", label: "Critical", icon: AlertCircle, colorClass: "text-severity-critical" },
  { key: "high", label: "High", icon: AlertTriangle, colorClass: "text-severity-high" },
  { key: "medium", label: "Medium", icon: ShieldCheck, colorClass: "text-severity-medium" },
] as const

export function StatsRow({ total, kev, critical, high, medium }: StatsRowProps) {
  const values: Record<string, number> = { total, kev, critical, high, medium }

  return (
    <div className="flex gap-3 px-5 py-3 shrink-0">
      {stats.map((stat) => (
        <div
          key={stat.key}
          className="flex flex-1 items-center gap-3 rounded-lg border border-border bg-card px-4 py-3 transition-all hover:-translate-y-0.5 hover:shadow-sm"
        >
          <stat.icon className={`h-5 w-5 shrink-0 ${stat.colorClass}`} />
          <div className="flex flex-col">
            <span className={`font-mono text-xl font-bold leading-none ${stat.colorClass}`}>
              {values[stat.key].toLocaleString()}
            </span>
            <span className="mt-0.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              {stat.label}
            </span>
          </div>
        </div>
      ))}
    </div>
  )
}
