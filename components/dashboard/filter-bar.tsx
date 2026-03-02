"use client"

import { Search } from "lucide-react"

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"

interface FilterBarProps {
  activeSeverities: Severity[]
  toggleSeverity: (s: Severity) => void
  kevOnly: boolean
  toggleKev: () => void
  searchQuery: string
  setSearchQuery: (q: string) => void
}

const severityPills: { severity: Severity; label: string; activeClasses: string; borderColor: string }[] = [
  {
    severity: "CRITICAL",
    label: "Critical",
    activeClasses: "bg-severity-critical text-white border-severity-critical",
    borderColor: "border-severity-critical text-severity-critical",
  },
  {
    severity: "HIGH",
    label: "High",
    activeClasses: "bg-severity-high text-white border-severity-high",
    borderColor: "border-severity-high text-severity-high",
  },
  {
    severity: "MEDIUM",
    label: "Medium",
    activeClasses: "bg-severity-medium text-foreground border-severity-medium",
    borderColor: "border-severity-medium text-severity-medium",
  },
  {
    severity: "LOW",
    label: "Low",
    activeClasses: "bg-severity-low text-white border-severity-low",
    borderColor: "border-severity-low text-severity-low",
  },
]

export function FilterBar({
  activeSeverities,
  toggleSeverity,
  kevOnly,
  toggleKev,
  searchQuery,
  setSearchQuery,
}: FilterBarProps) {
  return (
    <div className="flex items-center gap-2 border-b border-border px-5 py-2.5 shrink-0">
      {severityPills.map((pill) => {
        const isActive = activeSeverities.includes(pill.severity)
        return (
          <button
            key={pill.severity}
            onClick={() => toggleSeverity(pill.severity)}
            className={`rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-wider transition-all ${
              isActive ? pill.activeClasses : pill.borderColor
            }`}
          >
            {pill.label}
          </button>
        )
      })}

      <div className="mx-1 h-5 w-px bg-border" />

      <button
        onClick={toggleKev}
        className={`rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-wider transition-all ${
          kevOnly
            ? "border-severity-critical bg-severity-critical text-white"
            : "border-severity-critical text-severity-critical"
        }`}
      >
        KEV
      </button>

      <div className="ml-auto flex items-center">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search CVE, vendor, product..."
            className="h-8 w-64 rounded-lg border border-input bg-background pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
      </div>
    </div>
  )
}
