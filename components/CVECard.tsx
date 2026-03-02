import type { CVERow } from '@/lib/db/cves';
import SeverityBadge from './SeverityBadge';
import { AlertTriangle, ExternalLink } from 'lucide-react';

interface CVECardProps {
  cve: CVERow;
  compact?: boolean;
  onSelect?: (id: string) => void;
}

export default function CVECard({ cve, compact, onSelect }: CVECardProps) {
  const description = cve.description_en || 'No description available.';
  const truncated = compact
    ? description.slice(0, 120) + (description.length > 120 ? '...' : '')
    : description.slice(0, 250) + (description.length > 250 ? '...' : '');

  return (
    <article
      onClick={() => onSelect?.(cve.cve_id)}
      className={`card-dark p-4 ${onSelect ? 'cursor-pointer' : ''} ${compact ? 'p-3' : ''}`}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="cve-id text-sm font-semibold text-blue-400 shrink-0">{cve.cve_id}</span>
          {cve.is_kev && (
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-[10px] font-bold text-red-400 uppercase shrink-0">
              <AlertTriangle size={10} />
              KEV
            </span>
          )}
        </div>
        <SeverityBadge severity={cve.cvss_best_severity} score={cve.cvss_best_score} />
      </div>

      {/* Vendor / Product */}
      {(cve.primary_vendor || cve.primary_product) && (
        <div className="flex items-center gap-1.5 mb-2">
          <span className="text-[11px] text-zinc-500">
            {cve.primary_vendor}{cve.primary_product ? ` / ${cve.primary_product}` : ''}
          </span>
        </div>
      )}

      {/* Description */}
      <p className="text-xs text-zinc-400 leading-relaxed mb-3">{truncated}</p>

      {/* Footer */}
      <div className="flex items-center justify-between">
        <time className="text-[10px] text-zinc-600 font-mono">
          {cve.published
            ? new Date(cve.published).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
            : 'Unknown date'}
        </time>
        <a
          href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="text-[10px] text-zinc-500 hover:text-blue-400 transition-colors flex items-center gap-1"
        >
          NVD <ExternalLink size={10} />
        </a>
      </div>
    </article>
  );
}
