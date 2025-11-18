'use server'

import Groq from 'groq-sdk';

// Initialize Groq client
const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

export interface VulnerabilityData {
  id: string;
  title: string;
  description: string;
  severity: string;
  published: string;
  source: string;
  link: string;
  cveId?: string;
  cvssScore?: number;
  product?: string;
  vendor?: string;
  dueDate?: string;
}

export interface VulnerabilitySummary {
  vulnerability: VulnerabilityData;
  summary: string;
  generatedAt: string;
  trustedReferences?: TrustedReference[];
  error?: boolean;
}

export interface TrustedReference {
  url: string;
  source: string;
  tags: string[];
}

// Trusted sources for vulnerability information
const TRUSTED_SOURCES = [
  'nvd.nist.gov',
  'cisa.gov',
  'cve.mitre.org',
  'us-cert.cisa.gov',
  'kb.cert.org',
  'securityfocus.com',
  'exploit-db.com',
  'rapid7.com',
  'tenable.com',
  'qualys.com',
  'securelist.com',
  'zerodayinitiative.com',
  'microsoft.com/security',
  'oracle.com/security',
  'cisco.com/security',
  'apache.org/security',
  'redhat.com/security'
];

async function fetchVulnerabilityDetails(cveId: string): Promise<any> {
  try {
    const nvdResponse = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
      {
        headers: { 'User-Agent': 'VulnerabilityAISummary/1.0' },
        next: { revalidate: 3600 }
      }
    );

    if (nvdResponse.ok) {
      const data = await nvdResponse.json();
      return data.vulnerabilities?.[0]?.cve || null;
    }
  } catch (error) {
    console.error(`Error fetching details for ${cveId}:`, error);
  }
  return null;
}

async function generateAISummary(vulnerability: VulnerabilityData, detailedInfo: any): Promise<string> {
  const prompt = `
You are a cybersecurity expert analyzing vulnerability data. Create a comprehensive but concise summary of this vulnerability using ONLY information from trusted security sources.

VULNERABILITY INFORMATION:
- CVE ID: ${vulnerability.cveId || 'Not specified'}
- Title: ${vulnerability.title}
- Severity: ${vulnerability.severity}
- CVSS Score: ${vulnerability.cvssScore || 'Not available'}
- Affected Product: ${vulnerability.vendor ? vulnerability.vendor + ' ' : ''}${vulnerability.product || 'Not specified'}
- Source: ${vulnerability.source}
- Published Date: ${vulnerability.published}
${vulnerability.dueDate ? `- Due Date for Patching: ${vulnerability.dueDate}` : ''}

DESCRIPTION:
${vulnerability.description}

${detailedInfo ? `
ADDITIONAL DETAILS:
- Attack Vector: ${detailedInfo.metrics?.cvssMetricV31?.[0]?.cvssData?.attackVector || detailedInfo.metrics?.cvssMetricV30?.[0]?.cvssData?.attackVector || 'Unknown'}
- Attack Complexity: ${detailedInfo.metrics?.cvssMetricV31?.[0]?.cvssData?.attackComplexity || detailedInfo.metrics?.cvssMetricV30?.[0]?.cvssData?.attackComplexity || 'Unknown'}
- Privileges Required: ${detailedInfo.metrics?.cvssMetricV31?.[0]?.cvssData?.privilegesRequired || detailedInfo.metrics?.cvssMetricV30?.[0]?.cvssData?.privilegesRequired || 'Unknown'}
- User Interaction: ${detailedInfo.metrics?.cvssMetricV31?.[0]?.cvssData?.userInteraction || detailedInfo.metrics?.cvssMetricV30?.[0]?.cvssData?.userInteraction || 'Unknown'}
- Impact Scope: ${detailedInfo.metrics?.cvssMetricV31?.[0]?.cvssData?.scope || 'Unknown'}
- References Available: ${detailedInfo.references?.length || 0} sources
` : ''}

Please provide a structured security analysis that includes:

1. **THREAT OVERVIEW**: What is the core security risk? What can attackers achieve?

2. **TECHNICAL DETAILS**: 
   - How does the vulnerability work technically?
   - What are the prerequisites for exploitation?
   - What is the attack vector and complexity?

3. **IMPACT ASSESSMENT**:
   - What systems/data could be compromised?
   - What is the potential business impact?
   - Why is this rated as ${vulnerability.severity} severity?

4. **AFFECTED SYSTEMS**:
   - Specific versions and configurations at risk
   - Common deployment scenarios affected

5. **MITIGATION STRATEGY**:
   - Immediate actions required
   - Available patches or workarounds
   - Detection methods
 
   
6. **PRIORITY ASSESSMENT**:
   - How urgent is remediation?
   - Risk factors specific to this vulnerability

CRITICAL REQUIREMENTS:
- Only use verified information from trusted sources
- Be technically precise and actionable
- Do not speculate if information is unavailable
- Format with clear headers and bullet points where appropriate
- Keep total summary under 400 words
- Focus on practical, actionable intelligence`;

  try {
    const completion = await groq.chat.completions.create({
      messages: [
        {
          role: "system",
          content: "You are a senior cybersecurity analyst providing threat intelligence briefings. Your analysis must be accurate, technical, and actionable. Only reference verified information from trusted sources like CISA, NVD, CVE, and official vendor advisories."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      model: "llama-3.3-70b-versatile",
      temperature: 0.2,
      max_tokens: 1200,
      top_p: 0.9,
    });

    return completion.choices[0]?.message?.content || 'Unable to generate summary';
  } catch (error) {
    console.error('Error generating AI summary:', error);
    throw new Error('Failed to generate AI summary');
  }
}

export async function generateSingleVulnerabilitySummary(vulnerability: VulnerabilityData): Promise<VulnerabilitySummary> {
  try {
    // Fetch additional details if CVE ID is available
    let detailedInfo = null;
    let trustedReferences: TrustedReference[] = [];
    
    if (vulnerability.cveId) {
      detailedInfo = await fetchVulnerabilityDetails(vulnerability.cveId);
      
      // Extract trusted source references
      if (detailedInfo?.references) {
        trustedReferences = detailedInfo.references
          .filter((ref: any) => 
            TRUSTED_SOURCES.some(domain => ref.url?.includes(domain))
          )
          .slice(0, 8)
          .map((ref: any) => ({
            url: ref.url,
            source: ref.source || 'External',
            tags: ref.tags || []
          }));
      }
    }

    // Generate AI summary
    const summary = await generateAISummary(vulnerability, detailedInfo);

    return {
      vulnerability,
      summary,
      generatedAt: new Date().toISOString(),
      trustedReferences,
      error: false
    };
  } catch (error) {
    console.error(`Error generating summary for ${vulnerability.id}:`, error);
    return {
      vulnerability,
      summary: 'Failed to generate AI summary. Please try again.',
      generatedAt: new Date().toISOString(),
      error: true
    };
  }
}

export async function fetchLatestVulnerabilitiesWithSummaries(limit: number = 10): Promise<{
  summaries: VulnerabilitySummary[];
  totalProcessed: number;
  timestamp: string;
  error?: string;
}> {
  try {
    // Fetch CISA KEV vulnerabilities
    const cisaResponse = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { 
        next: { revalidate: 1800 },
        cache: 'no-store'
      }
    );

    if (!cisaResponse.ok) {
      throw new Error('Failed to fetch CISA data');
    }

    const cisaData = await cisaResponse.json();
    
    // Get the most recent vulnerabilities
    const recentVulns = cisaData.vulnerabilities
      ?.slice(0, limit)
      .map((vuln: any) => ({
        id: vuln.cveID || `cisa-${Date.now()}-${Math.random()}`,
        title: vuln.vulnerabilityName || 'Unknown Vulnerability',
        description: vuln.shortDescription || 'No description available',
        severity: 'Critical', // CISA KEV are all critical
        published: vuln.dateAdded,
        source: 'CISA KEV',
        link: `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`,
        cveId: vuln.cveID,
        product: vuln.product,
        vendor: vuln.vendorProject,
        dueDate: vuln.dueDate
      })) || [];

    // Also fetch some high-severity NVD vulnerabilities
    let nvdVulns: VulnerabilityData[] = [];
    try {
      const nvdResponse = await fetch(
        'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5&startIndex=0',
        {
          headers: { 'User-Agent': 'VulnerabilityAISummary/1.0' },
          next: { revalidate: 1800 }
        }
      );

      if (nvdResponse.ok) {
        const nvdData = await nvdResponse.json();
        nvdVulns = nvdData.vulnerabilities
          ?.slice(0, 5)
          .map((item: any) => {
            const vuln = item.cve;
            const description = vuln.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available';
            const cvssScore = vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                             vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore;
            
            return {
              id: vuln.id,
              title: vuln.id,
              description: description.substring(0, 500),
              severity: cvssScore >= 9 ? 'Critical' : cvssScore >= 7 ? 'High' : cvssScore >= 4 ? 'Medium' : 'Low',
              published: vuln.published,
              source: 'NVD',
              link: `https://nvd.nist.gov/vuln/detail/${vuln.id}`,
              cveId: vuln.id,
              cvssScore: cvssScore
            };
          })
          .filter((v: VulnerabilityData) => v.severity === 'Critical' || v.severity === 'High') || [];
      }
    } catch (nvdError) {
      console.error('Error fetching NVD data:', nvdError);
    }

    // Combine and limit vulnerabilities
    const allVulns = [...recentVulns, ...nvdVulns].slice(0, limit);

    // Generate summaries for each vulnerability
    const summariesPromises = allVulns.map(vuln => generateSingleVulnerabilitySummary(vuln));
    const summaries = await Promise.all(summariesPromises);

    return {
      summaries,
      totalProcessed: summaries.length,
      timestamp: new Date().toISOString()
    };

  } catch (error) {
    console.error('Error fetching and summarizing vulnerabilities:', error);
    return {
      summaries: [],
      totalProcessed: 0,
      timestamp: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Failed to fetch vulnerabilities'
    };
  }
}

export async function regenerateVulnerabilitySummary(vulnerability: VulnerabilityData): Promise<VulnerabilitySummary> {
  return generateSingleVulnerabilitySummary(vulnerability);
}