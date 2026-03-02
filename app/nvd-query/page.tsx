'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { ArrowLeft, Search, RefreshCw, Download, ExternalLink } from 'lucide-react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface QueryParams {
  cveId?: string;
  cpeName?: string;
  isVulnerable?: boolean;
  versionStart?: string;
  versionStartType?: 'including' | 'excluding';
  versionEnd?: string;
  versionEndType?: 'including' | 'excluding';
  cvssV3Severity?: string;
  cweId?: string;
  pubStartDate?: string;
  pubEndDate?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;
  keywordSearch?: string;
  keywordExactMatch?: boolean;
  sourceIdentifier?: string;
  hasKev?: boolean;
  hasCertAlerts?: boolean;
  hasCertNotes?: boolean;
  hasOval?: boolean;
  noRejected?: boolean;
  cveTag?: string;
  resultsPerPage?: number;
  startIndex?: number;
}

interface VulnResult {
  id: string;
  description: string;
  severity: string;
  published: string;
  lastModified: string;
  cvssScore?: number;
  cvssVector?: string;
  cweId?: string;
  isKev?: boolean;
  references: { url: string; tags: string[] }[];
}

interface QueryResponse {
  results: VulnResult[];
  totalResults: number;
  resultsPerPage: number;
  startIndex: number;
  timestamp: string;
  ingested?: number;
  error?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function sevBadge(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return 'bg-severity-critical/10 text-severity-critical border-severity-critical/20';
    case 'HIGH': return 'bg-severity-high/10 text-severity-high border-severity-high/20';
    case 'MEDIUM': return 'bg-severity-medium/10 text-severity-medium border-severity-medium/20';
    case 'LOW': return 'bg-severity-low/10 text-severity-low border-severity-low/20';
    default: return 'bg-gray-100 text-muted-foreground';
  }
}
function sevColor(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return 'text-severity-critical';
    case 'HIGH': return 'text-severity-high';
    case 'MEDIUM': return 'text-severity-medium';
    case 'LOW': return 'text-severity-low';
    default: return 'text-foreground';
  }
}

const INPUT = 'w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary font-mono';
const LABEL = 'block text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-1';

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function NVDQueryPage() {
  const [tab, setTab] = useState<'basic' | 'advanced' | 'filters'>('basic');
  const [params, setParams] = useState<QueryParams>({
    resultsPerPage: 20,
    startIndex: 0,
    noRejected: true,
  });
  const [results, setResults] = useState<QueryResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState('');
  const [apiKeyStored, setApiKeyStored] = useState(false);
  const [showKeyInput, setShowKeyInput] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    const k = localStorage.getItem('nvd_api_key');
    if (k) { setApiKey(k); setApiKeyStored(true); }
  }, []);

  const set = (patch: Partial<QueryParams>) => setParams((p) => ({ ...p, ...patch }));

  const handleQuery = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/nvd-query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(apiKey && { 'X-NVD-API-Key': apiKey }),
        },
        body: JSON.stringify(params),
      });
      const data: QueryResponse = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      setResults(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setParams({ resultsPerPage: 20, startIndex: 0, noRejected: true });
    setResults(null);
    setError(null);
    setExpandedId(null);
  };

  const handleExport = (format: 'json' | 'csv') => {
    if (!results) return;
    let content: string, filename: string, mime: string;
    if (format === 'json') {
      content = JSON.stringify(results, null, 2);
      filename = `nvd-query-${Date.now()}.json`;
      mime = 'application/json';
    } else {
      const hdr = ['CVE ID', 'Severity', 'Score', 'Published', 'Description'];
      const rows = results.results.map((r) => [
        r.id, r.severity, r.cvssScore?.toString() || '', r.published,
        `"${r.description.replace(/"/g, '""')}"`,
      ]);
      content = [hdr.join(','), ...rows.map((r) => r.join(','))].join('\n');
      filename = `nvd-query-${Date.now()}.csv`;
      mime = 'text/csv';
    }
    const blob = new Blob([content], { type: mime });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const saveKey = () => {
    if (apiKey.trim()) {
      localStorage.setItem('nvd_api_key', apiKey.trim());
      setApiKeyStored(true);
      setShowKeyInput(false);
    }
  };
  const removeKey = () => {
    localStorage.removeItem('nvd_api_key');
    setApiKey('');
    setApiKeyStored(false);
    setShowKeyInput(false);
  };

  const totalPages = results ? Math.ceil(results.totalResults / (results.resultsPerPage || 20)) : 0;
  const currentPage = results ? Math.floor((results.startIndex || 0) / (results.resultsPerPage || 20)) + 1 : 1;
  const goPage = (p: number) => {
    const perPage = params.resultsPerPage || 20;
    set({ startIndex: (p - 1) * perPage });
    setTimeout(handleQuery, 50);
  };

  return (
    <div className="grid-bg flex h-screen flex-col overflow-hidden">
      {/* Top bar */}
      <header className="flex h-[60px] shrink-0 items-center justify-between border-b border-border px-5">
        <div className="flex items-center gap-3">
          <Link href="/" className="flex items-center">
            <Image src="/Logo-SECFORIT.png" alt="SECFORIT" width={140} height={38} className="h-8 w-auto" priority />
          </Link>
          <div className="h-5 w-px bg-border" />
          <span className="text-lg font-light tracking-tight text-muted-foreground">NVD Query</span>
        </div>
        <div className="flex items-center gap-2">
          {apiKeyStored ? (
            <>
              <span className="text-[10px] font-semibold uppercase tracking-wider text-severity-low">API Key Set</span>
              <button onClick={() => setShowKeyInput(!showKeyInput)} className="text-xs text-muted-foreground hover:text-foreground">Edit</button>
              <button onClick={removeKey} className="text-xs text-severity-critical hover:underline">Remove</button>
            </>
          ) : (
            <button
              onClick={() => setShowKeyInput(!showKeyInput)}
              className="inline-flex items-center gap-1 rounded-lg bg-severity-medium px-3 py-1.5 text-xs font-semibold text-foreground transition-all hover:shadow-md"
            >
              + API Key
            </button>
          )}
        </div>
      </header>

      {/* API Key input */}
      {showKeyInput && (
        <div className="flex items-center gap-2 border-b border-border bg-card px-5 py-2 shrink-0">
          <span className="text-xs text-muted-foreground">Key:</span>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="NVD API key..."
            className={`${INPUT} max-w-md`}
            onKeyDown={(e) => e.key === 'Enter' && saveKey()}
          />
          <button onClick={saveKey} className="rounded-md bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground">Save</button>
          <button onClick={() => setShowKeyInput(false)} className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
          <span className="text-[10px] text-muted-foreground ml-2">Free key at nvd.nist.gov — 50 req/30s</span>
        </div>
      )}

      {/* Tabs + actions */}
      <div className="flex items-center border-b border-border px-5 shrink-0">
        <div className="flex">
          {(['basic', 'advanced', 'filters'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2.5 text-xs font-semibold uppercase tracking-wider transition-colors border-b-2 ${
                tab === t
                  ? 'text-primary border-primary'
                  : 'text-muted-foreground border-transparent hover:text-foreground'
              }`}
            >
              {t}
            </button>
          ))}
        </div>
        <div className="flex-1" />
        <div className="flex items-center gap-2 py-2">
          {results && (
            <>
              <button onClick={() => handleExport('json')} className="inline-flex items-center gap-1 rounded-lg border border-border px-2.5 py-1 text-xs text-foreground hover:bg-card">
                <Download className="h-3 w-3" /> JSON
              </button>
              <button onClick={() => handleExport('csv')} className="inline-flex items-center gap-1 rounded-lg border border-border px-2.5 py-1 text-xs text-foreground hover:bg-card">
                <Download className="h-3 w-3" /> CSV
              </button>
            </>
          )}
          <button onClick={handleReset} className="inline-flex items-center gap-1 rounded-lg border border-border px-2.5 py-1 text-xs text-foreground hover:bg-card">
            <RefreshCw className="h-3 w-3" /> Reset
          </button>
          <button
            onClick={handleQuery}
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-3.5 py-1.5 text-xs font-semibold text-primary-foreground transition-all hover:shadow-[0_0_30px_rgba(220,38,38,0.4)] disabled:opacity-60"
          >
            <Search className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Querying...' : 'Query NVD'}
          </button>
        </div>
      </div>

      {/* Query form */}
      <div className="border-b border-border bg-card/50 px-5 py-3 shrink-0 overflow-y-auto max-h-[240px]">
        {tab === 'basic' && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <div>
              <label className={LABEL}>CVE ID</label>
              <input className={INPUT} placeholder="CVE-2024-1234" value={params.cveId || ''} onChange={(e) => set({ cveId: e.target.value || undefined })} />
            </div>
            <div>
              <label className={LABEL}>Keyword Search</label>
              <input className={INPUT} placeholder="Search descriptions..." value={params.keywordSearch || ''} onChange={(e) => set({ keywordSearch: e.target.value || undefined })} />
              <label className="flex items-center gap-1.5 mt-1.5 text-[10px] text-muted-foreground">
                <input type="checkbox" checked={params.keywordExactMatch || false} onChange={(e) => set({ keywordExactMatch: e.target.checked })} className="accent-primary rounded" />
                Exact match
              </label>
            </div>
            <div>
              <label className={LABEL}>Published After</label>
              <input type="date" className={INPUT} value={params.pubStartDate || ''} onChange={(e) => set({ pubStartDate: e.target.value || undefined })} />
            </div>
            <div>
              <label className={LABEL}>Published Before</label>
              <input type="date" className={INPUT} value={params.pubEndDate || ''} onChange={(e) => set({ pubEndDate: e.target.value || undefined })} />
            </div>
            <div>
              <label className={LABEL}>CVSS v3 Severity</label>
              <select className={INPUT} value={params.cvssV3Severity || ''} onChange={(e) => set({ cvssV3Severity: e.target.value || undefined })}>
                <option value="">All</option>
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
                <option value="CRITICAL">Critical</option>
              </select>
            </div>
            <div>
              <label className={LABEL}>Results Per Page</label>
              <input type="number" className={INPUT} min={1} max={2000} value={params.resultsPerPage || 20} onChange={(e) => set({ resultsPerPage: parseInt(e.target.value) || 20 })} />
            </div>
          </div>
        )}

        {tab === 'advanced' && (
          <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
            <div>
              <label className={LABEL}>CPE Name</label>
              <input className={INPUT} placeholder="cpe:2.3:o:microsoft:windows_10:*" value={params.cpeName || ''} onChange={(e) => set({ cpeName: e.target.value || undefined })} />
              <label className="flex items-center gap-1.5 mt-1.5 text-[10px] text-muted-foreground">
                <input type="checkbox" checked={params.isVulnerable || false} onChange={(e) => set({ isVulnerable: e.target.checked })} className="accent-primary rounded" />
                Only vulnerable
              </label>
            </div>
            <div>
              <label className={LABEL}>CWE ID</label>
              <input className={INPUT} placeholder="CWE-79, CWE-89" value={params.cweId || ''} onChange={(e) => set({ cweId: e.target.value || undefined })} />
            </div>
            <div>
              <label className={LABEL}>Source Identifier</label>
              <input className={INPUT} placeholder="[email protected]" value={params.sourceIdentifier || ''} onChange={(e) => set({ sourceIdentifier: e.target.value || undefined })} />
            </div>
            <div>
              <label className={LABEL}>Version Start</label>
              <div className="flex gap-1">
                <input className={`${INPUT} flex-1`} placeholder="2.6" value={params.versionStart || ''} onChange={(e) => set({ versionStart: e.target.value || undefined })} />
                <select className={`${INPUT} w-20`} value={params.versionStartType || 'including'} onChange={(e) => set({ versionStartType: e.target.value as any })}>
                  <option value="including">incl</option>
                  <option value="excluding">excl</option>
                </select>
              </div>
            </div>
            <div>
              <label className={LABEL}>Version End</label>
              <div className="flex gap-1">
                <input className={`${INPUT} flex-1`} placeholder="2.7" value={params.versionEnd || ''} onChange={(e) => set({ versionEnd: e.target.value || undefined })} />
                <select className={`${INPUT} w-20`} value={params.versionEndType || 'excluding'} onChange={(e) => set({ versionEndType: e.target.value as any })}>
                  <option value="including">incl</option>
                  <option value="excluding">excl</option>
                </select>
              </div>
            </div>
            <div>
              <label className={LABEL}>Last Modified After</label>
              <input type="date" className={INPUT} value={params.lastModStartDate || ''} onChange={(e) => set({ lastModStartDate: e.target.value || undefined })} />
              <label className={`${LABEL} mt-2`}>Last Modified Before</label>
              <input type="date" className={INPUT} value={params.lastModEndDate || ''} onChange={(e) => set({ lastModEndDate: e.target.value || undefined })} />
            </div>
          </div>
        )}

        {tab === 'filters' && (
          <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
            <div className="space-y-2">
              <span className={LABEL}>Quick Filters</span>
              {([
                ['hasKev', 'CISA KEV Listed'],
                ['noRejected', 'Exclude Rejected'],
                ['hasCertAlerts', 'Has CERT Alerts'],
                ['hasCertNotes', 'Has CERT Notes'],
                ['hasOval', 'Has OVAL Data'],
              ] as const).map(([key, label]) => (
                <label key={key} className="flex items-center gap-2 text-xs text-foreground cursor-pointer hover:text-primary transition-colors">
                  <input
                    type="checkbox"
                    checked={!!(params as any)[key]}
                    onChange={(e) => set({ [key]: e.target.checked || undefined })}
                    className="accent-primary rounded"
                  />
                  {label}
                </label>
              ))}
            </div>
            <div>
              <label className={LABEL}>CVE Tag</label>
              <select className={INPUT} value={params.cveTag || ''} onChange={(e) => set({ cveTag: e.target.value || undefined })}>
                <option value="">None</option>
                <option value="disputed">Disputed</option>
                <option value="unsupported-when-assigned">Unsupported When Assigned</option>
                <option value="exclusively-hosted-service">Exclusively Hosted Service</option>
              </select>
            </div>
            <div>
              <label className={LABEL}>Start Index</label>
              <input type="number" className={INPUT} min={0} value={params.startIndex || 0} onChange={(e) => set({ startIndex: parseInt(e.target.value) || 0 })} />
            </div>
          </div>
        )}
      </div>

      {/* Status line */}
      {(error || results) && (
        <div className={`shrink-0 border-b border-border px-5 py-1.5 text-xs ${error ? 'text-severity-critical bg-severity-critical/5' : 'text-muted-foreground bg-card'}`}>
          {error
            ? `Error: ${error}`
            : `${results!.totalResults.toLocaleString()} results found — showing ${results!.results.length} — ${results!.ingested || 0} persisted to DB — ${new Date(results!.timestamp).toLocaleTimeString()}`}
        </div>
      )}

      {/* Results table header */}
      <div className="grid grid-cols-[130px_60px_90px_1fr_90px] gap-3 border-b border-border bg-card/50 px-5 py-2.5 shrink-0">
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">CVE-ID</span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Score</span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Severity</span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Description</span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground text-right">Published</span>
      </div>

      {/* Results body */}
      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center py-20 text-sm text-muted-foreground">
            <svg className="mr-2 h-4 w-4 animate-spin text-primary" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Querying NVD API...
          </div>
        ) : results && results.results.length > 0 ? (
          results.results.map((v) => (
            <div key={v.id}>
              <button
                onClick={() => setExpandedId(expandedId === v.id ? null : v.id)}
                className="w-full grid grid-cols-[130px_60px_90px_1fr_90px] gap-3 px-5 py-2.5 text-left border-b border-border/60 transition-colors hover:bg-card group"
              >
                <div className="flex items-center gap-1.5">
                  <span className="font-mono text-xs font-semibold text-foreground group-hover:text-primary transition-colors">
                    {v.id}
                  </span>
                  {v.isKev && (
                    <span className="rounded bg-severity-critical px-1.5 py-0.5 text-[9px] font-bold uppercase leading-none text-white">KEV</span>
                  )}
                </div>
                <span className={`font-mono text-sm font-bold ${sevColor(v.severity)}`}>
                  {v.cvssScore?.toFixed(1) ?? '—'}
                </span>
                <span className={`inline-flex self-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${sevBadge(v.severity)}`}>
                  {v.severity}
                </span>
                <span className="truncate text-xs text-muted-foreground self-center">
                  {v.description.length > 120 ? v.description.slice(0, 120) + '...' : v.description}
                </span>
                <span className="text-xs text-muted-foreground text-right self-center">
                  {v.published ? new Date(v.published).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—'}
                </span>
              </button>

              {expandedId === v.id && (
                <div className="border-b border-border bg-card px-5 py-3 text-xs space-y-2">
                  <p className="text-foreground leading-relaxed">{v.description}</p>
                  <div className="flex flex-wrap gap-3 text-[11px]">
                    {v.cvssVector && <span className="text-muted-foreground"><span className="font-semibold text-foreground">Vector:</span> {v.cvssVector}</span>}
                    {v.cweId && <span className={`rounded-full border px-2 py-0.5 ${sevBadge('MEDIUM')}`}>{v.cweId}</span>}
                    <span className="text-muted-foreground"><span className="font-semibold text-foreground">Modified:</span> {v.lastModified ? new Date(v.lastModified).toLocaleDateString('en-CA') : '—'}</span>
                  </div>
                  {v.references.length > 0 && (
                    <div className="space-y-0.5">
                      <span className="font-semibold text-foreground">References:</span>
                      {v.references.map((ref, i) => (
                        <div key={i}>
                          <a href={ref.url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline break-all">
                            {ref.url}
                          </a>
                          {ref.tags.length > 0 && <span className="text-muted-foreground ml-2">[{ref.tags.join(', ')}]</span>}
                        </div>
                      ))}
                    </div>
                  )}
                  <a href={`https://nvd.nist.gov/vuln/detail/${v.id}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline font-semibold">
                    View on NVD <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              )}
            </div>
          ))
        ) : results ? (
          <div className="flex items-center justify-center py-20 text-sm text-muted-foreground">
            No vulnerabilities found. Adjust your query parameters.
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
            <Search className="h-8 w-8 mb-3 text-border" />
            <p className="text-sm">Configure query above and click <span className="font-semibold text-primary">Query NVD</span></p>
            <p className="text-[11px] mt-1">Results are automatically persisted to your database</p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <footer className="flex h-11 shrink-0 items-center justify-between border-t border-border px-5">
          <span className="text-xs text-muted-foreground">
            <span className="font-semibold text-foreground">{(results!.startIndex + 1).toLocaleString()}–{Math.min(results!.startIndex + results!.results.length, results!.totalResults).toLocaleString()}</span> of <span className="font-semibold text-foreground">{results!.totalResults.toLocaleString()}</span>
          </span>
          <div className="flex items-center gap-2">
            <button onClick={() => goPage(currentPage - 1)} disabled={currentPage <= 1} className="inline-flex items-center gap-1 rounded-lg border border-border px-2.5 py-1 text-xs font-medium text-foreground hover:bg-card disabled:pointer-events-none disabled:opacity-40">Prev</button>
            <span className="text-xs text-muted-foreground">Page <span className="font-semibold text-foreground">{currentPage}</span>/{totalPages}</span>
            <button onClick={() => goPage(currentPage + 1)} disabled={currentPage >= totalPages} className="inline-flex items-center gap-1 rounded-lg border border-border px-2.5 py-1 text-xs font-medium text-foreground hover:bg-card disabled:pointer-events-none disabled:opacity-40">Next</button>
          </div>
        </footer>
      )}
    </div>
  );
}
