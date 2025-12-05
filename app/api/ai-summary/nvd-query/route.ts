import { NextRequest, NextResponse } from 'next/server';
import {
  fetchNVDRecent,
  fetchNVDByCVEIds,
  fetchNVDByCPE,
  fetchNVDByCWE
} from '@/lib/vulnerability-fetch';

interface QueryParams {
  // CVE Specific
  cveId?: string;
  
  // CPE Filters
  cpeName?: string;
  isVulnerable?: boolean;
  virtualMatchString?: string;
  
  // Version Filters
  versionStart?: string;
  versionStartType?: 'including' | 'excluding';
  versionEnd?: string;
  versionEndType?: 'including' | 'excluding';
  
  // CVSS Filters
  cvssV2Metrics?: string;
  cvssV2Severity?: 'LOW' | 'MEDIUM' | 'HIGH';
  cvssV3Metrics?: string;
  cvssV3Severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvssV4Metrics?: string;
  cvssV4Severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  
  // CWE Filter
  cweId?: string;
  
  // Date Filters
  pubStartDate?: string;
  pubEndDate?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;
  kevStartDate?: string;
  kevEndDate?: string;
  
  // Keyword Search
  keywordSearch?: string;
  keywordExactMatch?: boolean;
  
  // Source Filter
  sourceIdentifier?: string;
  
  // Boolean Filters
  hasKev?: boolean;
  hasCertAlerts?: boolean;
  hasCertNotes?: boolean;
  hasOval?: boolean;
  noRejected?: boolean;
  
  // CVE Tags
  cveTag?: 'disputed' | 'unsupported-when-assigned' | 'exclusively-hosted-service';
  
  // Pagination
  resultsPerPage?: number;
  startIndex?: number;
}

/**
 * Rate limiting for NVD API
 */
const NVD_API_KEY = process.env.NVD_API_KEY;
const NVD_RATE_LIMIT_DELAY = NVD_API_KEY ? 600 : 6000;
let lastNvdRequest = 0;

async function nvdRateLimit(): Promise<void> {
  const now = Date.now();
  const timeSinceLastRequest = now - lastNvdRequest;
  
  if (timeSinceLastRequest < NVD_RATE_LIMIT_DELAY) {
    const waitTime = NVD_RATE_LIMIT_DELAY - timeSinceLastRequest;
    await new Promise(resolve => setTimeout(resolve, waitTime));
  }
  
  lastNvdRequest = Date.now();
}

/**
 * Build NVD API URL with query parameters
 */
function buildNVDQueryURL(params: QueryParams): string {
  const baseURL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  const urlParams = new URLSearchParams();

  // Single CVE query
  if (params.cveId) {
    urlParams.append('cveId', params.cveId);
    return `${baseURL}?${urlParams.toString()}`;
  }

  // CPE filters
  if (params.cpeName) {
    urlParams.append('cpeName', params.cpeName);
  }
  if (params.virtualMatchString) {
    urlParams.append('virtualMatchString', params.virtualMatchString);
  }
  if (params.isVulnerable) {
    urlParams.append('isVulnerable', '');
  }

  // Version filters
  if (params.versionStart && params.versionStartType) {
    urlParams.append('versionStart', params.versionStart);
    urlParams.append('versionStartType', params.versionStartType);
  }
  if (params.versionEnd && params.versionEndType) {
    urlParams.append('versionEnd', params.versionEnd);
    urlParams.append('versionEndType', params.versionEndType);
  }

  // CVSS filters
  if (params.cvssV2Metrics) {
    urlParams.append('cvssV2Metrics', params.cvssV2Metrics);
  }
  if (params.cvssV2Severity) {
    urlParams.append('cvssV2Severity', params.cvssV2Severity);
  }
  if (params.cvssV3Metrics) {
    urlParams.append('cvssV3Metrics', params.cvssV3Metrics);
  }
  if (params.cvssV3Severity) {
    urlParams.append('cvssV3Severity', params.cvssV3Severity);
  }
  if (params.cvssV4Metrics) {
    urlParams.append('cvssV4Metrics', params.cvssV4Metrics);
  }
  if (params.cvssV4Severity) {
    urlParams.append('cvssV4Severity', params.cvssV4Severity);
  }

  // CWE filter
  if (params.cweId) {
    urlParams.append('cweId', params.cweId);
  }

  // Date filters
  if (params.pubStartDate && params.pubEndDate) {
    urlParams.append('pubStartDate', new Date(params.pubStartDate).toISOString());
    urlParams.append('pubEndDate', new Date(params.pubEndDate).toISOString());
  }
  if (params.lastModStartDate && params.lastModEndDate) {
    urlParams.append('lastModStartDate', new Date(params.lastModStartDate).toISOString());
    urlParams.append('lastModEndDate', new Date(params.lastModEndDate).toISOString());
  }
  if (params.kevStartDate && params.kevEndDate) {
    urlParams.append('kevStartDate', new Date(params.kevStartDate).toISOString());
    urlParams.append('kevEndDate', new Date(params.kevEndDate).toISOString());
  }

  // Keyword search
  if (params.keywordSearch) {
    urlParams.append('keywordSearch', params.keywordSearch);
    if (params.keywordExactMatch) {
      urlParams.append('keywordExactMatch', '');
    }
  }

  // Source filter
  if (params.sourceIdentifier) {
    urlParams.append('sourceIdentifier', params.sourceIdentifier);
  }

  // Boolean filters
  if (params.hasKev) {
    urlParams.append('hasKev', '');
  }
  if (params.hasCertAlerts) {
    urlParams.append('hasCertAlerts', '');
  }
  if (params.hasCertNotes) {
    urlParams.append('hasCertNotes', '');
  }
  if (params.hasOval) {
    urlParams.append('hasOval', '');
  }
  if (params.noRejected) {
    urlParams.append('noRejected', '');
  }

  // CVE Tag
  if (params.cveTag) {
    urlParams.append('cveTag', params.cveTag);
  }

  // Pagination
  const resultsPerPage = Math.min(params.resultsPerPage || 20, 2000);
  urlParams.append('resultsPerPage', resultsPerPage.toString());
  urlParams.append('startIndex', (params.startIndex || 0).toString());

  return `${baseURL}?${urlParams.toString()}`;
}

/**
 * Get NVD API headers with user's API key if provided
 */
function getNvdHeaders(userApiKey?: string): HeadersInit {
  const headers: HeadersInit = {
    'User-Agent': 'SecForIT-NVD-Query-Console/1.0'
  };
  
  // Prioritize user's API key over server key
  const apiKey = userApiKey || NVD_API_KEY;
  
  if (apiKey) {
    headers['apiKey'] = apiKey;
  }
  
  return headers;
}

/**
 * Execute NVD query
 */
async function executeNVDQuery(params: QueryParams, userApiKey?: string) {
  // Rate limiting
  await nvdRateLimit();

  // For complex queries, build custom URL
  const url = buildNVDQueryURL(params);
  
  const response = await fetch(url, {
    headers: getNvdHeaders(userApiKey),
    next: { revalidate: 1800 }
  });

  if (!response.ok) {
    throw new Error(`NVD API returned ${response.status}`);
  }

  const data = await response.json();

  const results = data.vulnerabilities?.map((item: any) => {
    const vuln = item.cve;
    const description = vuln.descriptions?.find((d: any) => d.lang === 'en')?.value || 
      'No description available';
    
    const cvssMetricV31 = vuln.metrics?.cvssMetricV31?.[0];
    const cvssMetricV30 = vuln.metrics?.cvssMetricV30?.[0];
    const cvssMetricV2 = vuln.metrics?.cvssMetricV2?.[0];
    
    const cvssScore = 
      cvssMetricV31?.cvssData?.baseScore ||
      cvssMetricV30?.cvssData?.baseScore ||
      cvssMetricV2?.cvssData?.baseScore;

    const cvssVector = 
      cvssMetricV31?.cvssData?.vectorString ||
      cvssMetricV30?.cvssData?.vectorString ||
      cvssMetricV2?.cvssData?.vectorString;

    let severity = 'Low';
    if (cvssScore) {
      if (cvssScore >= 9.0) severity = 'Critical';
      else if (cvssScore >= 7.0) severity = 'High';
      else if (cvssScore >= 4.0) severity = 'Medium';
    }

    const isKev = !!vuln.cisaExploitAdd;
    const cweId = vuln.weaknesses?.[0]?.description?.[0]?.value;

    return {
      id: vuln.id,
      title: vuln.id,
      description,
      severity,
      published: vuln.published,
      updated: vuln.lastModified,
      cvssScore,
      cvssVector,
      cweId,
      isKev,
      references: vuln.references?.map((ref: any) => ({
        url: ref.url,
        tags: ref.tags || []
      })) || []
    };
  }) || [];

  return {
    results,
    totalResults: data.totalResults || results.length,
    resultsPerPage: data.resultsPerPage || results.length,
    startIndex: data.startIndex || 0
  };
}

/**
 * POST handler - Execute query
 */
export async function POST(request: NextRequest) {
  try {
    const params: QueryParams = await request.json();
    
    // Extract user's API key from headers
    const userApiKey = request.headers.get('X-NVD-API-Key') || undefined;

    // Validate date ranges (NVD limit is 120 days)
    if (params.pubStartDate && params.pubEndDate) {
      const start = new Date(params.pubStartDate);
      const end = new Date(params.pubEndDate);
      const daysDiff = Math.floor((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
      
      if (daysDiff > 120) {
        return NextResponse.json(
          { error: 'Date range cannot exceed 120 days (NVD API limit)' },
          { status: 400 }
        );
      }
    }

    // Execute query with user's API key
    const result = await executeNVDQuery(params, userApiKey);

    return NextResponse.json({
      ...result,
      timestamp: new Date().toISOString(),
      query: params,
      usingApiKey: !!userApiKey
    });

  } catch (error) {
    console.error('NVD query error:', error);
    return NextResponse.json(
      { 
        error: 'Query failed',
        details: error instanceof Error ? error.message : 'Unknown error',
        results: [],
        totalResults: 0,
        resultsPerPage: 0,
        startIndex: 0,
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}

/**
 * GET handler - Return query builder interface info
 */
export async function GET(request: NextRequest) {
  // Check if user provided their API key
  const userApiKey = request.headers.get('X-NVD-API-Key');
  const hasUserKey = !!userApiKey;
  const hasServerKey = !!NVD_API_KEY;

  const apiConfig = {
    rateLimit: hasUserKey || hasServerKey ? '50 requests/30s' : '5 requests/30s',
    hasApiKey: hasUserKey || hasServerKey,
    hasUserApiKey: hasUserKey,
    maxDateRange: 120,
    maxResultsPerPage: 2000,
    recommendation: !hasUserKey ? 'Add your personal NVD API key for higher rate limits' : 'Using your personal API key',
    supportedFilters: {
      cveId: 'Specific CVE identifier',
      cpeName: 'Common Platform Enumeration',
      cweId: 'Common Weakness Enumeration',
      cvssV3Severity: 'CVSS v3 severity level',
      dateRange: 'Publication or modification date range',
      keywordSearch: 'Text search in descriptions',
      hasKev: 'CISA Known Exploited Vulnerabilities',
      hasCertAlerts: 'US-CERT technical alerts',
      hasCertNotes: 'CERT/CC vulnerability notes',
      hasOval: 'OVAL assessment data',
      noRejected: 'Exclude rejected CVEs'
    },
    examples: [
      {
        name: 'Recent Critical Vulnerabilities',
        params: {
          cvssV3Severity: 'CRITICAL',
          pubStartDate: '2024-01-01',
          pubEndDate: '2024-12-31',
          resultsPerPage: 20
        }
      },
      {
        name: 'CISA KEV Vulnerabilities',
        params: {
          hasKev: true,
          resultsPerPage: 50
        }
      },
      {
        name: 'Windows 10 Vulnerabilities',
        params: {
          cpeName: 'cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*',
          isVulnerable: true,
          resultsPerPage: 30
        }
      },
      {
        name: 'SQL Injection Vulnerabilities',
        params: {
          cweId: 'CWE-89',
          cvssV3Severity: 'HIGH',
          resultsPerPage: 25
        }
      }
    ]
  };

  return NextResponse.json(apiConfig);
}