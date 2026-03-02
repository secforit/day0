"use client"

import { useState, useEffect, useCallback } from "react"
import { TopBar } from "@/components/dashboard/top-bar"
import { StatsRow } from "@/components/dashboard/stats-row"
import { FilterBar, type Severity } from "@/components/dashboard/filter-bar"
import { CVETable } from "@/components/dashboard/cve-table"
import { PaginationFooter } from "@/components/dashboard/pagination-footer"

const PAGE_SIZE = 30

interface DashboardData {
  cves: any[]
  count: number
  stats: { cvss_best_severity: string; count: number }[]
  freshness: {
    totalCves: number
    latestIngested: string | null
    kevCount: number
  }
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)

  // Filters
  const [activeSeverities, setActiveSeverities] = useState<Severity[]>([])
  const [kevOnly, setKevOnly] = useState(false)
  const [searchQuery, setSearchQuery] = useState("")
  const [searchDebounced, setSearchDebounced] = useState("")
  const [currentPage, setCurrentPage] = useState(1)

  // Debounce search
  useEffect(() => {
    const t = setTimeout(() => {
      setSearchDebounced(searchQuery)
      setCurrentPage(1)
    }, 400)
    return () => clearTimeout(t)
  }, [searchQuery])

  // Fetch data from API
  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      if (activeSeverities.length > 0) {
        params.set("severity", activeSeverities.join(","))
      }
      if (kevOnly) params.set("kev", "true")
      if (searchDebounced) params.set("search", searchDebounced)
      params.set("page", String(currentPage))
      params.set("limit", String(PAGE_SIZE))

      const res = await fetch(`/api/dashboard?${params}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json: DashboardData = await res.json()
      setData(json)
    } catch (err) {
      console.error("Dashboard fetch error:", err)
    } finally {
      setLoading(false)
    }
  }, [activeSeverities, kevOnly, searchDebounced, currentPage])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const toggleSeverity = useCallback((severity: Severity) => {
    setActiveSeverities((prev) =>
      prev.includes(severity)
        ? prev.filter((s) => s !== severity)
        : [...prev, severity]
    )
    setCurrentPage(1)
  }, [])

  const toggleKev = useCallback(() => {
    setKevOnly((prev) => !prev)
    setCurrentPage(1)
  }, [])

  const handleSearchChange = useCallback((q: string) => {
    setSearchQuery(q)
  }, [])

  // Derive stats
  const statMap = (data?.stats || []).reduce(
    (acc, s) => {
      acc[s.cvss_best_severity] = s.count
      return acc
    },
    {} as Record<string, number>
  )

  const totalPages = data ? Math.max(1, Math.ceil(data.count / PAGE_SIZE)) : 1

  return (
    <div className="grid-bg flex h-screen flex-col overflow-hidden">
      <TopBar lastSync={data?.freshness.latestIngested || null} />

      <StatsRow
        total={data?.freshness.totalCves || 0}
        kev={data?.freshness.kevCount || 0}
        critical={statMap["CRITICAL"] || 0}
        high={statMap["HIGH"] || 0}
        medium={statMap["MEDIUM"] || 0}
      />

      <FilterBar
        activeSeverities={activeSeverities}
        toggleSeverity={toggleSeverity}
        kevOnly={kevOnly}
        toggleKev={toggleKev}
        searchQuery={searchQuery}
        setSearchQuery={handleSearchChange}
      />

      <CVETable data={data?.cves || []} loading={loading && !data} />

      <PaginationFooter
        currentPage={currentPage}
        totalPages={totalPages}
        totalItems={data?.count || 0}
        pageSize={PAGE_SIZE}
        onPageChange={setCurrentPage}
      />
    </div>
  )
}
