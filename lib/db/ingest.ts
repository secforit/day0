import { supabaseAdmin } from '@/lib/supabase';

/**
 * Parse a raw NVD CVE item and upsert into all related tables.
 * Expects the `cve` object from the NVD API response (item.cve).
 */
export async function ingestNVDCVE(nvdCve: any, kevData?: {
  dateAdded?: string;
  dueDate?: string;
  requiredAction?: string;
  knownRansomwareUse?: string;
  vulnerabilityName?: string;
}): Promise<{ cveId: string; error: string | null }> {
  const admin = supabaseAdmin();
  const cveId = nvdCve.id;

  // Extract English description
  const descriptionEn = nvdCve.descriptions?.find((d: any) => d.lang === 'en')?.value || null;

  // Extract best CVSS score (v4 > v3.1 > v3.0 > v2)
  const { bestScore, bestSeverity } = extractBestCVSS(nvdCve.metrics);

  // Extract primary vendor/product from configurations
  const { vendor, product } = extractPrimaryVendorProduct(nvdCve.configurations);

  // Check KEV status
  const isKev = !!nvdCve.cisaExploitAdd || !!kevData;

  // Upsert the main CVE record
  const { error: cveError } = await admin
    .from('cves')
    .upsert({
      cve_id: cveId,
      description_en: descriptionEn,
      cvss_best_score: bestScore,
      cvss_best_severity: bestSeverity,
      published: nvdCve.published,
      last_modified: nvdCve.lastModified,
      source_identifier: nvdCve.sourceIdentifier,
      vuln_status: nvdCve.vulnStatus,
      is_kev: isKev,
      cisa_date_added: kevData?.dateAdded || nvdCve.cisaExploitAdd || null,
      cisa_due_date: kevData?.dueDate || nvdCve.cisaActionDue || null,
      cisa_required_action: kevData?.requiredAction || nvdCve.cisaRequiredAction || null,
      cisa_known_ransomware_use: kevData?.knownRansomwareUse || null,
      cisa_vulnerability_name: kevData?.vulnerabilityName || null,
      primary_vendor: vendor,
      primary_product: product,
      raw_data: nvdCve,
      configurations: nvdCve.configurations || null,
      metrics: nvdCve.metrics || null,
    }, { onConflict: 'cve_id' });

  if (cveError) {
    console.error(`Error upserting CVE ${cveId}:`, cveError);
    return { cveId, error: cveError.message };
  }

  // Upsert related tables in parallel
  await Promise.allSettled([
    upsertReferences(admin, cveId, nvdCve.references),
    upsertWeaknesses(admin, cveId, nvdCve.weaknesses),
    upsertCVSSMetrics(admin, cveId, nvdCve.metrics),
    upsertCPEMatches(admin, cveId, nvdCve.configurations),
  ]);

  return { cveId, error: null };
}

/**
 * Batch ingest multiple NVD CVEs
 */
export async function ingestNVDBatch(
  nvdItems: any[],
  kevLookup?: Map<string, any>
): Promise<{ ingested: number; errors: string[] }> {
  const errors: string[] = [];
  let ingested = 0;

  for (const item of nvdItems) {
    const cve = item.cve || item;
    const cveId = cve.id;
    const kevInfo = kevLookup?.get(cveId);

    const result = await ingestNVDCVE(cve, kevInfo ? {
      dateAdded: kevInfo.dateAdded,
      dueDate: kevInfo.dueDate,
      requiredAction: kevInfo.requiredAction,
      knownRansomwareUse: kevInfo.knownRansomwareCampaignUse,
      vulnerabilityName: kevInfo.vulnerabilityName,
    } : undefined);

    if (result.error) {
      errors.push(`${cveId}: ${result.error}`);
    } else {
      ingested++;
    }
  }

  return { ingested, errors };
}

/**
 * Ingest CISA KEV catalog into the database
 * Marks CVEs as KEV and stores CISA-specific fields
 */
export async function ingestCISAKEV(kevVulnerabilities: any[]): Promise<{
  updated: number;
  errors: string[];
}> {
  const admin = supabaseAdmin();
  const errors: string[] = [];
  let updated = 0;

  for (const kev of kevVulnerabilities) {
    const cveId = kev.cveID;

    const { error } = await admin
      .from('cves')
      .upsert({
        cve_id: cveId,
        is_kev: true,
        cisa_date_added: kev.dateAdded,
        cisa_due_date: kev.dueDate,
        cisa_required_action: kev.requiredAction,
        cisa_known_ransomware_use: kev.knownRansomwareCampaignUse,
        cisa_vulnerability_name: kev.vulnerabilityName,
        description_en: kev.shortDescription || null,
        primary_vendor: kev.vendorProject || null,
        primary_product: kev.product || null,
      }, { onConflict: 'cve_id' });

    if (error) {
      errors.push(`${cveId}: ${error.message}`);
    } else {
      updated++;
    }
  }

  return { updated, errors };
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

function extractBestCVSS(metrics: any): { bestScore: number | null; bestSeverity: string } {
  if (!metrics) return { bestScore: null, bestSeverity: 'UNKNOWN' };

  // Priority: v4 > v3.1 > v3.0 > v2
  const v4 = metrics.cvssMetricV40?.[0];
  const v31 = metrics.cvssMetricV31?.[0];
  const v30 = metrics.cvssMetricV30?.[0];
  const v2 = metrics.cvssMetricV2?.[0];

  const metric = v4 || v31 || v30 || v2;
  if (!metric) return { bestScore: null, bestSeverity: 'UNKNOWN' };

  const score = metric.cvssData?.baseScore || null;
  let severity = metric.cvssData?.baseSeverity || metric.baseSeverity || 'UNKNOWN';

  // Normalize severity
  severity = severity.toUpperCase();
  if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'].includes(severity)) {
    // Derive from score
    if (score !== null) {
      if (score >= 9.0) severity = 'CRITICAL';
      else if (score >= 7.0) severity = 'HIGH';
      else if (score >= 4.0) severity = 'MEDIUM';
      else if (score > 0) severity = 'LOW';
      else severity = 'NONE';
    } else {
      severity = 'UNKNOWN';
    }
  }

  return { bestScore: score, bestSeverity: severity };
}

function extractPrimaryVendorProduct(configurations: any): { vendor: string | null; product: string | null } {
  if (!configurations) return { vendor: null, product: null };

  // Walk through configuration nodes to find the first vulnerable CPE
  for (const node of configurations) {
    for (const n of (node.nodes || [node])) {
      for (const match of (n.cpeMatch || [])) {
        if (match.vulnerable) {
          const parts = (match.criteria || '').split(':');
          if (parts.length >= 5) {
            return {
              vendor: parts[3] !== '*' ? parts[3] : null,
              product: parts[4] !== '*' ? parts[4] : null,
            };
          }
        }
      }
    }
  }

  return { vendor: null, product: null };
}

async function upsertReferences(admin: any, cveId: string, references: any[]) {
  if (!references || references.length === 0) return;

  // Delete existing then insert (simpler than individual upserts)
  await admin.from('cve_references').delete().eq('cve_id', cveId);

  const rows = references.map((ref: any) => ({
    cve_id: cveId,
    url: ref.url,
    source: ref.source || null,
    tags: ref.tags || [],
  }));

  const { error } = await admin.from('cve_references').insert(rows);
  if (error) console.error(`Error inserting references for ${cveId}:`, error);
}

async function upsertWeaknesses(admin: any, cveId: string, weaknesses: any[]) {
  if (!weaknesses || weaknesses.length === 0) return;

  await admin.from('cve_weaknesses').delete().eq('cve_id', cveId);

  const rows: any[] = [];
  for (const weakness of weaknesses) {
    for (const desc of (weakness.description || [])) {
      rows.push({
        cve_id: cveId,
        cwe_id: desc.value,
        source: weakness.source || null,
        source_type: weakness.type || null,
      });
    }
  }

  if (rows.length > 0) {
    const { error } = await admin.from('cve_weaknesses').insert(rows);
    if (error) console.error(`Error inserting weaknesses for ${cveId}:`, error);
  }
}

async function upsertCVSSMetrics(admin: any, cveId: string, metrics: any) {
  if (!metrics) return;

  await admin.from('cvss_metrics').delete().eq('cve_id', cveId);

  const rows: any[] = [];

  const metricVersions = [
    { key: 'cvssMetricV2', version: 'v2.0' },
    { key: 'cvssMetricV30', version: 'v3.0' },
    { key: 'cvssMetricV31', version: 'v3.1' },
    { key: 'cvssMetricV40', version: 'v4.0' },
  ] as const;

  for (const { key, version } of metricVersions) {
    const items = metrics[key];
    if (!items) continue;

    for (const item of items) {
      rows.push({
        cve_id: cveId,
        version,
        source: item.source || null,
        source_type: item.type || null,
        base_score: item.cvssData?.baseScore || null,
        base_severity: item.cvssData?.baseSeverity || item.baseSeverity || null,
        vector_string: item.cvssData?.vectorString || null,
        exploitability_score: item.exploitabilityScore || null,
        impact_score: item.impactScore || null,
        metric_data: item,
      });
    }
  }

  if (rows.length > 0) {
    const { error } = await admin.from('cvss_metrics').insert(rows);
    if (error) console.error(`Error inserting CVSS metrics for ${cveId}:`, error);
  }
}

async function upsertCPEMatches(admin: any, cveId: string, configurations: any) {
  if (!configurations) return;

  await admin.from('cve_cpe_matches').delete().eq('cve_id', cveId);

  const rows: any[] = [];

  for (const config of configurations) {
    for (const node of (config.nodes || [config])) {
      for (const match of (node.cpeMatch || [])) {
        const parts = (match.criteria || '').split(':');
        rows.push({
          cve_id: cveId,
          vendor: parts.length > 3 && parts[3] !== '*' ? parts[3] : null,
          product: parts.length > 4 && parts[4] !== '*' ? parts[4] : null,
          criteria: match.criteria,
          vulnerable: match.vulnerable ?? true,
          version_start_including: match.versionStartIncluding || null,
          version_start_excluding: match.versionStartExcluding || null,
          version_end_including: match.versionEndIncluding || null,
          version_end_excluding: match.versionEndExcluding || null,
          match_criteria_id: match.matchCriteriaId || null,
        });
      }
    }
  }

  if (rows.length > 0) {
    const { error } = await admin.from('cve_cpe_matches').insert(rows);
    if (error) console.error(`Error inserting CPE matches for ${cveId}:`, error);
  }
}
