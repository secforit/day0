import { NextRequest, NextResponse } from 'next/server';
import { ingestCISAKEV, ingestNVDBatch, ingestNVDCVE } from '@/lib/db/ingest';
import { supabaseClient } from '@/lib/supabase';

const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

export const maxDuration = 300;

function authenticate(request: NextRequest): boolean {
  const ingestSecret = process.env.INGEST_SECRET;
  if (!ingestSecret) return false;

  const authHeader = request.headers.get('Authorization');
  const url = new URL(request.url);
  const queryToken = url.searchParams.get('token');
  const provided = authHeader?.replace('Bearer ', '') || queryToken;

  return provided === ingestSecret;
}

async function handleIngest() {
  const start = Date.now();
  const nvdApiKey = process.env.NVD_API_KEY;
  const delay = nvdApiKey ? 600 : 6000;
  const nvdHeaders: Record<string, string> = {};
  if (nvdApiKey) nvdHeaders['apiKey'] = nvdApiKey;

  try {
    // 1. Fetch CISA KEV catalog
    const cisaRes = await fetch(CISA_KEV_URL, { cache: 'no-store' });
    if (!cisaRes.ok) {
      return NextResponse.json(
        { error: `CISA KEV fetch failed: ${cisaRes.status}` },
        { status: 502 }
      );
    }
    const cisaJson = await cisaRes.json();
    const kevVulnerabilities = cisaJson.vulnerabilities || [];

    const cisaResult = await ingestCISAKEV(kevVulnerabilities);

    // 2. Build KEV lookup map for cross-referencing with NVD data
    const kevLookup = new Map<string, any>();
    for (const kev of kevVulnerabilities) {
      kevLookup.set(kev.cveID, kev);
    }

    // 3. Fetch NVD Critical CVEs (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const pubStartDate = thirtyDaysAgo.toISOString().slice(0, 23);
    const pubEndDate = new Date().toISOString().slice(0, 23);

    const criticalUrl = `${NVD_API_URL}?cvssV3Severity=CRITICAL&pubStartDate=${pubStartDate}&pubEndDate=${pubEndDate}&resultsPerPage=200`;
    const criticalRes = await fetch(criticalUrl, { headers: nvdHeaders, cache: 'no-store' });

    let nvdCriticalResult = { ingested: 0, errors: [] as string[] };
    if (criticalRes.ok) {
      const criticalJson = await criticalRes.json();
      const criticalItems = criticalJson.vulnerabilities || [];
      nvdCriticalResult = await ingestNVDBatch(criticalItems, kevLookup);
    }

    // 4. Rate-limit pause before next NVD request
    await new Promise((resolve) => setTimeout(resolve, delay));

    // 5. Fetch NVD High CVEs (last 30 days)
    const highUrl = `${NVD_API_URL}?cvssV3Severity=HIGH&pubStartDate=${pubStartDate}&pubEndDate=${pubEndDate}&resultsPerPage=200`;
    const highRes = await fetch(highUrl, { headers: nvdHeaders, cache: 'no-store' });

    let nvdHighResult = { ingested: 0, errors: [] as string[] };
    if (highRes.ok) {
      const highJson = await highRes.json();
      const highItems = highJson.vulnerabilities || [];
      nvdHighResult = await ingestNVDBatch(highItems, kevLookup);
    }

    // 6. Enrich KEV entries missing full NVD data (raw_data IS NULL means
    //    the entry was created by CISA KEV ingest but never enriched with
    //    NVD details: CVSS scores, references, weaknesses, CPE matches, etc.)
    await new Promise((resolve) => setTimeout(resolve, delay));

    const db = supabaseClient();
    const { data: unenriched } = await db
      .from('cves')
      .select('cve_id')
      .eq('is_kev', true)
      .is('raw_data', null)
      .order('cisa_date_added', { ascending: false })
      .limit(50);

    let kevEnriched = 0;
    const kevEnrichErrors: string[] = [];

    if (unenriched && unenriched.length > 0) {
      for (const { cve_id } of unenriched) {
        try {
          await new Promise((resolve) => setTimeout(resolve, delay));

          const nvdRes = await fetch(
            `${NVD_API_URL}?cveId=${cve_id}`,
            { headers: nvdHeaders, cache: 'no-store' }
          );

          if (nvdRes.ok) {
            const nvdJson = await nvdRes.json();
            const items = nvdJson.vulnerabilities || [];
            if (items.length > 0) {
              const cve = items[0].cve;
              const kevInfo = kevLookup.get(cve_id);
              const result = await ingestNVDCVE(cve, kevInfo ? {
                dateAdded: kevInfo.dateAdded,
                dueDate: kevInfo.dueDate,
                requiredAction: kevInfo.requiredAction,
                knownRansomwareUse: kevInfo.knownRansomwareCampaignUse,
                vulnerabilityName: kevInfo.vulnerabilityName,
              } : undefined);

              if (result.error) {
                kevEnrichErrors.push(`${cve_id}: ${result.error}`);
              } else {
                kevEnriched++;
              }
            }
          }
        } catch (err: any) {
          kevEnrichErrors.push(`${cve_id}: ${err.message}`);
        }
      }
    }

    const durationMs = Date.now() - start;

    return NextResponse.json({
      ok: true,
      cisaKev: cisaResult.updated,
      nvdCritical: nvdCriticalResult.ingested,
      nvdHigh: nvdHighResult.ingested,
      kevEnriched,
      totalIngested: cisaResult.updated + nvdCriticalResult.ingested + nvdHighResult.ingested + kevEnriched,
      durationMs,
      errors: [
        ...cisaResult.errors,
        ...nvdCriticalResult.errors,
        ...nvdHighResult.errors,
        ...kevEnrichErrors,
      ].slice(0, 20),
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message || 'Ingestion failed', durationMs: Date.now() - start },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  if (!authenticate(request)) {
    return NextResponse.json({ error: 'Unauthorized — set INGEST_SECRET and provide it via Authorization header or ?token= param' }, { status: 401 });
  }
  return handleIngest();
}

export async function GET(request: NextRequest) {
  if (!authenticate(request)) {
    return NextResponse.json({ error: 'Unauthorized — set INGEST_SECRET and provide it via Authorization header or ?token= param' }, { status: 401 });
  }
  return handleIngest();
}
