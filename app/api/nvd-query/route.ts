import { NextRequest, NextResponse } from 'next/server';
import { ingestNVDBatch } from '@/lib/db/ingest';

interface QueryParams {
  cveId?: string;
  cpeName?: string;
  isVulnerable?: boolean;
  virtualMatchString?: string;
  versionStart?: string;
  versionStartType?: 'including' | 'excluding';
  versionEnd?: string;
  versionEndType?: 'including' | 'excluding';
  cvssV2Metrics?: string;
  cvssV2Severity?: string;
  cvssV3Metrics?: string;
  cvssV3Severity?: string;
  cvssV4Metrics?: string;
  cvssV4Severity?: string;
  cweId?: string;
  pubStartDate?: string;
  pubEndDate?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;
  kevStartDate?: string;
  kevEndDate?: string;
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

const NVD_API_KEY = process.env.NVD_API_KEY;
const NVD_RATE_LIMIT_DELAY = NVD_API_KEY ? 600 : 6000;
let lastNvdRequest = 0;

async function nvdRateLimit(): Promise<void> {
  const now = Date.now();
  const elapsed = now - lastNvdRequest;
  if (elapsed < NVD_RATE_LIMIT_DELAY) {
    await new Promise((r) => setTimeout(r, NVD_RATE_LIMIT_DELAY - elapsed));
  }
  lastNvdRequest = Date.now();
}

function buildNVDQueryURL(params: QueryParams): string {
  const base = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  const u = new URLSearchParams();

  if (params.cveId) {
    u.append('cveId', params.cveId);
    return `${base}?${u}`;
  }

  if (params.cpeName) u.append('cpeName', params.cpeName);
  if (params.virtualMatchString) u.append('virtualMatchString', params.virtualMatchString);
  if (params.isVulnerable) u.append('isVulnerable', '');
  if (params.versionStart && params.versionStartType) {
    u.append('versionStart', params.versionStart);
    u.append('versionStartType', params.versionStartType);
  }
  if (params.versionEnd && params.versionEndType) {
    u.append('versionEnd', params.versionEnd);
    u.append('versionEndType', params.versionEndType);
  }
  if (params.cvssV2Metrics) u.append('cvssV2Metrics', params.cvssV2Metrics);
  if (params.cvssV2Severity) u.append('cvssV2Severity', params.cvssV2Severity);
  if (params.cvssV3Metrics) u.append('cvssV3Metrics', params.cvssV3Metrics);
  if (params.cvssV3Severity) u.append('cvssV3Severity', params.cvssV3Severity);
  if (params.cvssV4Metrics) u.append('cvssV4Metrics', params.cvssV4Metrics);
  if (params.cvssV4Severity) u.append('cvssV4Severity', params.cvssV4Severity);
  if (params.cweId) u.append('cweId', params.cweId);
  if (params.pubStartDate && params.pubEndDate) {
    u.append('pubStartDate', new Date(params.pubStartDate).toISOString());
    u.append('pubEndDate', new Date(params.pubEndDate).toISOString());
  }
  if (params.lastModStartDate && params.lastModEndDate) {
    u.append('lastModStartDate', new Date(params.lastModStartDate).toISOString());
    u.append('lastModEndDate', new Date(params.lastModEndDate).toISOString());
  }
  if (params.kevStartDate && params.kevEndDate) {
    u.append('kevStartDate', new Date(params.kevStartDate).toISOString());
    u.append('kevEndDate', new Date(params.kevEndDate).toISOString());
  }
  if (params.keywordSearch) {
    u.append('keywordSearch', params.keywordSearch);
    if (params.keywordExactMatch) u.append('keywordExactMatch', '');
  }
  if (params.sourceIdentifier) u.append('sourceIdentifier', params.sourceIdentifier);
  if (params.hasKev) u.append('hasKev', '');
  if (params.hasCertAlerts) u.append('hasCertAlerts', '');
  if (params.hasCertNotes) u.append('hasCertNotes', '');
  if (params.hasOval) u.append('hasOval', '');
  if (params.noRejected) u.append('noRejected', '');
  if (params.cveTag) u.append('cveTag', params.cveTag);

  u.append('resultsPerPage', String(Math.min(params.resultsPerPage || 20, 2000)));
  u.append('startIndex', String(params.startIndex || 0));

  return `${base}?${u}`;
}

export async function POST(request: NextRequest) {
  // Protect endpoint — require INGEST_SECRET or user's own NVD API key
  const ingestSecret = process.env.INGEST_SECRET;
  const userApiKey = request.headers.get('X-NVD-API-Key') || undefined;

  if (ingestSecret && !userApiKey) {
    const authHeader = request.headers.get('Authorization');
    const provided = authHeader?.replace('Bearer ', '');
    if (provided !== ingestSecret) {
      return NextResponse.json({ error: 'Provide your own NVD API key or authenticate' }, { status: 401 });
    }
  }

  try {
    const params: QueryParams = await request.json();

    if (params.pubStartDate && params.pubEndDate) {
      const days = Math.floor(
        (new Date(params.pubEndDate).getTime() - new Date(params.pubStartDate).getTime()) /
          (1000 * 60 * 60 * 24)
      );
      if (days > 120) {
        return NextResponse.json(
          { error: 'Date range cannot exceed 120 days (NVD API limit)' },
          { status: 400 }
        );
      }
    }

    await nvdRateLimit();

    const url = buildNVDQueryURL(params);
    const headers: Record<string, string> = { 'User-Agent': 'SecForIT-NVD-Console/1.0' };
    const apiKey = userApiKey || NVD_API_KEY;
    if (apiKey) headers['apiKey'] = apiKey;

    const res = await fetch(url, { headers, cache: 'no-store' });
    if (!res.ok) {
      return NextResponse.json(
        { error: `NVD API returned ${res.status}: ${res.statusText}` },
        { status: 502 }
      );
    }

    const data = await res.json();
    const rawItems = data.vulnerabilities || [];

    // Persist fetched CVEs to Supabase in the background
    if (rawItems.length > 0) {
      ingestNVDBatch(rawItems).catch((e) =>
        console.error('Background NVD ingestion error:', e)
      );
    }

    const results = rawItems.map((item: any) => {
      const vuln = item.cve;
      const description =
        vuln.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available';
      const cvssScore =
        vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
        vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ||
        vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore;
      const cvssVector =
        vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.vectorString ||
        vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.vectorString ||
        vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.vectorString;

      let severity = 'LOW';
      if (cvssScore >= 9.0) severity = 'CRITICAL';
      else if (cvssScore >= 7.0) severity = 'HIGH';
      else if (cvssScore >= 4.0) severity = 'MEDIUM';

      return {
        id: vuln.id,
        description,
        severity,
        published: vuln.published,
        lastModified: vuln.lastModified,
        cvssScore,
        cvssVector,
        cweId: vuln.weaknesses?.[0]?.description?.[0]?.value,
        isKev: !!vuln.cisaExploitAdd,
        references: (vuln.references || []).slice(0, 5).map((r: any) => ({
          url: r.url,
          tags: r.tags || [],
        })),
      };
    });

    return NextResponse.json({
      results,
      totalResults: data.totalResults || 0,
      resultsPerPage: data.resultsPerPage || results.length,
      startIndex: data.startIndex || 0,
      timestamp: new Date().toISOString(),
      ingested: rawItems.length,
    });
  } catch (err: any) {
    console.error('NVD query error:', err);
    return NextResponse.json(
      { error: err.message || 'Query failed', results: [], totalResults: 0 },
      { status: 500 }
    );
  }
}
