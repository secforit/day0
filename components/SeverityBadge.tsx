const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-green-500/15 text-green-400 border-green-500/30',
  NONE: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
  UNKNOWN: 'bg-zinc-500/15 text-zinc-500 border-zinc-500/30',
};

export default function SeverityBadge({
  severity,
  score,
}: {
  severity: string | null;
  score?: number | null;
}) {
  const key = (severity || 'UNKNOWN').toUpperCase();
  const style = SEVERITY_STYLES[key] || SEVERITY_STYLES.UNKNOWN;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wide border ${style}`}>
      {key}
      {score != null && <span className="font-mono">{score.toFixed(1)}</span>}
    </span>
  );
}
