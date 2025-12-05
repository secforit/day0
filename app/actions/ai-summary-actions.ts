'use server'

import Groq from 'groq-sdk';
import { fetchCISAVulnerabilities, fetchRecentNVDVulnerabilities, fetchCVEDetails } from '@/lib/vulnerability-fetch';

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
      detailedInfo = await fetchCVEDetails(vulnerability.cveId);
      
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
    // Fetch recent vulnerabilities from both sources
    // CISA: Get latest exploited vulnerabilities
    // NVD: Get vulnerabilities from last 30 days with CVSS >= 7.0
    const [cisaVulns, nvdVulns] = await Promise.all([
      fetchCISAVulnerabilities(Math.ceil(limit * 0.6)), // 60% from CISA
      fetchRecentNVDVulnerabilities(30, Math.ceil(limit * 0.4), 7.0) // 40% from NVD, min CVSS 7.0
    ]);

    // Combine and limit vulnerabilities
    const allVulns = [...cisaVulns, ...nvdVulns]
      .sort((a, b) => new Date(b.published).getTime() - new Date(a.published).getTime())
      .slice(0, limit);

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