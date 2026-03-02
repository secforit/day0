"use client"

import { Database } from "lucide-react"
import Image from "next/image"
import Link from "next/link"

interface TopBarProps {
  lastSync: string | null
}

export function TopBar({ lastSync }: TopBarProps) {
  const syncTime = lastSync
    ? new Date(lastSync).toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : "Never"

  return (
    <header className="flex h-[60px] shrink-0 items-center justify-between border-b border-border px-5">
      <div className="flex items-center gap-3">
        <Image
          src="/Logo-SECFORIT.png"
          alt="SECFORIT"
          width={140}
          height={38}
          className="h-8 w-auto"
          priority
        />
        <span className="text-lg font-light tracking-tight text-muted-foreground">
          ZeroDay
        </span>
      </div>

      <div className="flex items-center gap-2.5">
        <span className="relative flex h-2.5 w-2.5">
          <span className="animate-pulse-live absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
          <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-primary" />
        </span>
        <span className="text-xs font-semibold uppercase tracking-wider text-primary">
          Live
        </span>
        <span className="text-xs text-muted-foreground">
          Last sync: {syncTime}
        </span>
      </div>

      <div className="flex items-center gap-2">
        <Link
          href="/nvd-query"
          className="inline-flex items-center gap-1.5 rounded-lg border border-foreground px-3.5 py-1.5 text-xs font-semibold text-foreground transition-all hover:bg-foreground hover:text-background"
        >
          <Database className="h-3.5 w-3.5" />
          NVD Query
        </Link>
      </div>
    </header>
  )
}
