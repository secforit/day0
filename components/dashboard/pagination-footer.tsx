"use client"

import { ChevronLeft, ChevronRight } from "lucide-react"

interface PaginationFooterProps {
  currentPage: number
  totalPages: number
  totalItems: number
  pageSize: number
  onPageChange: (page: number) => void
}

export function PaginationFooter({
  currentPage,
  totalPages,
  totalItems,
  pageSize,
  onPageChange,
}: PaginationFooterProps) {
  const start = (currentPage - 1) * pageSize + 1
  const end = Math.min(currentPage * pageSize, totalItems)

  if (totalItems === 0) return null

  return (
    <footer className="flex h-11 shrink-0 items-center justify-between border-t border-border px-5">
      <span className="text-xs text-muted-foreground">
        Showing{" "}
        <span className="font-semibold text-foreground">{start}–{end}</span>{" "}
        of{" "}
        <span className="font-semibold text-foreground">{totalItems.toLocaleString()}</span>{" "}
        results
      </span>
      <div className="flex items-center gap-2">
        <button
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage <= 1}
          className="inline-flex items-center gap-1 rounded-lg border border-border px-2.5 py-1 text-xs font-medium text-foreground transition-colors hover:bg-card disabled:pointer-events-none disabled:opacity-40"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
          Prev
        </button>
        <span className="text-xs text-muted-foreground">
          Page <span className="font-semibold text-foreground">{currentPage}</span>/{totalPages}
        </span>
        <button
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage >= totalPages}
          className="inline-flex items-center gap-1 rounded-lg border border-border px-2.5 py-1 text-xs font-medium text-foreground transition-colors hover:bg-card disabled:pointer-events-none disabled:opacity-40"
        >
          Next
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </footer>
  )
}
