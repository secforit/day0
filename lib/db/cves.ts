import { supabaseAdmin, supabaseClient } from '@/lib/supabase';

export interface CVEQueryFilters {
  severity?: string[];
  minCvss?: number;
  maxCvss?: number;
  isKev?: boolean;
  vendor?: string;
  product?: string;
  cweId?: string;
  search?: string;
  publishedAfter?: string;
  publishedBefore?: string;
  sortBy?: 'published' | 'cvss_best_score' | 'last_modified';
  sortOrder?: 'asc' | 'desc';
  limit?: number;
  offset?: number;
}

export interface CVERow {
  cve_id: string;
  description_en: string | null;
  cvss_best_score: number | null;
  cvss_best_severity: string | null;
  published: string | null;
  last_modified: string | null;
  source_identifier: string | null;
  vuln_status: string | null;
  is_kev: boolean;
  cisa_date_added: string | null;
  cisa_due_date: string | null;
  cisa_required_action: string | null;
  cisa_known_ransomware_use: string | null;
  cisa_vulnerability_name: string | null;
  primary_vendor: string | null;
  primary_product: string | null;
  raw_data: any;
  configurations: any;
  metrics: any;
  ingested_at: string;
  updated_at: string;
}

/**
 * Query CVEs from the database with filters
 */
export async function queryCVEs(filters: CVEQueryFilters = {}): Promise<{
  data: CVERow[];
  count: number;
  error: string | null;
}> {
  const db = supabaseClient();
  const {
    severity,
    minCvss,
    maxCvss,
    isKev,
    vendor,
    product,
    cweId,
    search,
    publishedAfter,
    publishedBefore,
    sortBy = 'published',
    sortOrder = 'desc',
    limit = 50,
    offset = 0,
  } = filters;

  let query = db
    .from('cves')
    .select('*', { count: 'exact' });

  if (severity && severity.length > 0) {
    query = query.in('cvss_best_severity', severity.map(s => s.toUpperCase()));
  }
  if (minCvss !== undefined) {
    query = query.gte('cvss_best_score', minCvss);
  }
  if (maxCvss !== undefined) {
    query = query.lte('cvss_best_score', maxCvss);
  }
  if (isKev !== undefined) {
    query = query.eq('is_kev', isKev);
  }
  if (vendor) {
    query = query.ilike('primary_vendor', `%${vendor}%`);
  }
  if (product) {
    query = query.ilike('primary_product', `%${product}%`);
  }
  if (publishedAfter) {
    query = query.gte('published', publishedAfter);
  }
  if (publishedBefore) {
    query = query.lte('published', publishedBefore);
  }
  if (search) {
    query = query.textSearch('search_vector', search, { type: 'websearch' });
  }

  query = query
    .order(sortBy, { ascending: sortOrder === 'asc' })
    .range(offset, offset + limit - 1);

  const { data, count, error } = await query;

  if (error) {
    console.error('Error querying CVEs:', error);
    return { data: [], count: 0, error: error.message };
  }

  // If CWE filter requested, do a subquery join
  if (cweId && data) {
    const cveIds = data.map((d: any) => d.cve_id);
    const { data: cweMatches } = await db
      .from('cve_weaknesses')
      .select('cve_id')
      .eq('cwe_id', cweId)
      .in('cve_id', cveIds);

    const matchedIds = new Set(cweMatches?.map((m: any) => m.cve_id) || []);
    const filtered = data.filter((d: any) => matchedIds.has(d.cve_id));
    return { data: filtered as CVERow[], count: filtered.length, error: null };
  }

  return { data: (data || []) as CVERow[], count: count || 0, error: null };
}

/**
 * Get a single CVE by ID
 */
export async function getCVEById(cveId: string): Promise<CVERow | null> {
  const db = supabaseClient();
  const { data, error } = await db
    .from('cves')
    .select('*')
    .eq('cve_id', cveId)
    .single();

  if (error) {
    if (error.code === 'PGRST116') return null; // not found
    console.error(`Error fetching CVE ${cveId}:`, error);
    return null;
  }

  return data as CVERow;
}

/**
 * Get CVEs with their latest AI summaries
 */
export async function getCVEsWithSummaries(filters: CVEQueryFilters = {}): Promise<{
  data: any[];
  count: number;
  error: string | null;
}> {
  const db = supabaseClient();
  const {
    sortBy = 'published',
    sortOrder = 'desc',
    limit = 20,
    offset = 0,
    isKev,
    minCvss,
    severity,
  } = filters;

  let query = db
    .from('v_cves_with_summary')
    .select('*', { count: 'exact' });

  if (isKev !== undefined) query = query.eq('is_kev', isKev);
  if (minCvss !== undefined) query = query.gte('cvss_best_score', minCvss);
  if (severity && severity.length > 0) {
    query = query.in('cvss_best_severity', severity.map(s => s.toUpperCase()));
  }

  query = query
    .order(sortBy, { ascending: sortOrder === 'asc' })
    .range(offset, offset + limit - 1);

  const { data, count, error } = await query;

  if (error) {
    console.error('Error querying CVEs with summaries:', error);
    return { data: [], count: 0, error: error.message };
  }

  return { data: data || [], count: count || 0, error: null };
}

/**
 * Upsert a single CVE (server-side, uses admin client)
 */
export async function upsertCVE(cve: Partial<CVERow>): Promise<{ error: string | null }> {
  const admin = supabaseAdmin();
  const { error } = await admin
    .from('cves')
    .upsert(cve, { onConflict: 'cve_id' });

  if (error) {
    console.error(`Error upserting CVE ${cve.cve_id}:`, error);
    return { error: error.message };
  }

  return { error: null };
}

/**
 * Bulk upsert CVEs (server-side)
 */
export async function bulkUpsertCVEs(cves: Partial<CVERow>[]): Promise<{
  inserted: number;
  error: string | null;
}> {
  if (cves.length === 0) return { inserted: 0, error: null };

  const admin = supabaseAdmin();
  const { error } = await admin
    .from('cves')
    .upsert(cves, { onConflict: 'cve_id' });

  if (error) {
    console.error('Error bulk upserting CVEs:', error);
    return { inserted: 0, error: error.message };
  }

  return { inserted: cves.length, error: null };
}

/**
 * Search CVEs by vendor/product using the CPE matches table
 */
export async function searchByVendorProduct(
  vendor?: string,
  product?: string,
  limit: number = 50
): Promise<CVERow[]> {
  const db = supabaseClient();

  let query = db
    .from('cve_cpe_matches')
    .select('cve_id');

  if (vendor) query = query.ilike('vendor', `%${vendor}%`);
  if (product) query = query.ilike('product', `%${product}%`);

  const { data: matches, error } = await query.limit(limit);

  if (error || !matches || matches.length === 0) return [];

  const cveIds = [...new Set(matches.map((m: any) => m.cve_id))];

  const { data: cves } = await db
    .from('cves')
    .select('*')
    .in('cve_id', cveIds)
    .order('cvss_best_score', { ascending: false });

  return (cves || []) as CVERow[];
}

/**
 * Get severity distribution stats
 */
export async function getSeverityStats(): Promise<any[]> {
  const db = supabaseClient();
  const { data, error } = await db
    .from('v_severity_stats')
    .select('*');

  if (error) {
    console.error('Error fetching severity stats:', error);
    return [];
  }

  return data || [];
}

/**
 * Get KEV vulnerabilities
 */
export async function getKEVVulnerabilities(limit: number = 20): Promise<any[]> {
  const db = supabaseClient();
  const { data, error } = await db
    .from('v_kev_vulnerabilities')
    .select('*')
    .limit(limit);

  if (error) {
    console.error('Error fetching KEV vulns:', error);
    return [];
  }

  return data || [];
}

/**
 * Check how stale our data is
 */
export async function getDataFreshness(): Promise<{
  totalCves: number;
  latestIngested: string | null;
  latestPublished: string | null;
  kevCount: number;
}> {
  const db = supabaseClient();

  const [countResult, latestResult, kevResult] = await Promise.all([
    db.from('cves').select('*', { count: 'exact', head: true }),
    db.from('cves').select('ingested_at, published').order('ingested_at', { ascending: false }).limit(1),
    db.from('cves').select('*', { count: 'exact', head: true }).eq('is_kev', true),
  ]);

  return {
    totalCves: countResult.count || 0,
    latestIngested: latestResult.data?.[0]?.ingested_at || null,
    latestPublished: latestResult.data?.[0]?.published || null,
    kevCount: kevResult.count || 0,
  };
}
