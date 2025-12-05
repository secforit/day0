import { NextRequest, NextResponse } from 'next/server';
import Groq from 'groq-sdk';

// Initialize Groq client
const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

interface VulnerabilityData {
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
  'zerodayinitiative.com'
];

async function fetchVulnerabilityDetails(cveId: string): Promise<any> {
  try {
    // Fetch detailed information from NVD
    const nvdResponse = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
      {
        headers: { 'User-Agent': 'VulnerabilityAISummary/1.0' }
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

DESCRIPTION:
${vulnerability.description}

${detailedInfo ? `
ADDITIONAL DETAILS:
- Attack Vector: ${detailedInfo.metrics?.cvssMetricV31?.[0]?.cvssData?.attackVector || 'Unknown'}
- Attack Complexity: ${detailedInfo.metrics?.cvssMetricV31?.[0]?.cvssData?.attackComplexity || 'Unknown'}
- Privileges Required: ${detailedInfo.metrics?.cvssMetricV31?.[0]?.cvssData?.privilegesRequired || 'Unknown'}
- User Interaction: ${detailedInfo.metrics?.cvssMetricV31?.[0]?.cvssData?.userInteraction || 'Unknown'}
- References: ${detailedInfo.references?.slice(0, 3).map((ref: any) => ref.url).join(', ') || 'None'}
` : ''}

Please provide a summary that includes:
1. **Critical Impact**: What is the main security risk and potential impact on affected systems?
2. **Attack Method**: How can this vulnerability be exploited?
3. **Affected Systems**: Which specific versions, products, or configurations are vulnerable?
4. **Risk Assessment**: Why is this vulnerability significant? What makes it critical/high/medium/low severity?
5. **Mitigation Priority**: How urgently should organizations address this?
6. **Recommended Actions**: What immediate steps should be taken?

IMPORTANT: 
- Only reference information from trusted sources (CISA, NVD, CVE, vendor advisories)
- Be specific about technical details when available
- If information is not available, do not speculate
- Format the response in clear, actionable sections
- Keep the summary under 300 words
`;

  try {
    const completion = await groq.chat.completions.create({
      messages: [
        {
          role: "system",
          content: "You are a cybersecurity expert that provides accurate, detailed vulnerability analysis based only on verified information from trusted sources. You never speculate or add unverified information."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      model: "mixtral-8x7b-32768",
      temperature: 0.3,
      max_tokens: 1000,
    });

    return completion.choices[0]?.message?.content || 'Unable to generate summary';
  } catch (error) {
    console.error('Error generating AI summary:', error);
    throw new Error('Failed to generate AI summary');
  }
}

export async function POST(request: NextRequest) {
  try {
    const { vulnerability } = await request.json();

    if (!vulnerability) {
      return NextResponse.json(
        { error: 'Vulnerability data is required' },
        { status: 400 }
      );
    }

    // Fetch additional details if CVE ID is available
    let detailedInfo = null;
    if (vulnerability.cveId) {
      detailedInfo = await fetchVulnerabilityDetails(vulnerability.cveId);
    }

    // Generate AI summary
    const summary = await generateAISummary(vulnerability, detailedInfo);

    // Extract trusted source references
    const trustedReferences = detailedInfo?.references
      ?.filter((ref: any) => 
        TRUSTED_SOURCES.some(domain => ref.url?.includes(domain))
      )
      .slice(0, 5)
      .map((ref: any) => ({
        url: ref.url,
        source: ref.source || 'External',
        tags: ref.tags || []
      })) || [];

    return NextResponse.json({
      success: true,
      summary,
      trustedReferences,
      metadata: {
        generatedAt: new Date().toISOString(),
        model: 'mixtral-8x7b-32768',
        cveId: vulnerability.cveId,
        severity: vulnerability.severity
      }
    });

  } catch (error) {
    console.error('Error in AI summary generation:', error);
    return NextResponse.json(
      { error: 'Failed to generate AI summary', details: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}

// GET endpoint to fetch vulnerabilities and generate summaries for all
export async function GET(request: NextRequest) {
  try {
    // Fetch CISA KEV vulnerabilities
    const cisaResponse = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { next: { revalidate: 3600 } }
    );

    if (!cisaResponse.ok) {
      throw new Error('Failed to fetch CISA data');
    }

    const cisaData = await cisaResponse.json();
    
    // Get the 5 most recent vulnerabilities
    const recentVulns = cisaData.vulnerabilities
      ?.slice(0, 5)
      .map((vuln: any) => ({
        id: vuln.cveID,
        title: vuln.vulnerabilityName,
        description: vuln.shortDescription,
        severity: 'Critical',
        published: vuln.dateAdded,
        source: 'CISA KEV',
        link: `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`,
        cveId: vuln.cveID,
        product: vuln.product,
        vendor: vuln.vendorProject,
        dueDate: vuln.dueDate
      })) || [];

    // Generate summaries for each vulnerability
    const summariesPromises = recentVulns.map(async (vuln: VulnerabilityData) => {
      try {
        const detailedInfo = vuln.cveId ? await fetchVulnerabilityDetails(vuln.cveId) : null;
        const summary = await generateAISummary(vuln, detailedInfo);
        
        return {
          vulnerability: vuln,
          summary,
          generatedAt: new Date().toISOString()
        };
      } catch (error) {
        console.error(`Error generating summary for ${vuln.id}:`, error);
        return {
          vulnerability: vuln,
          summary: 'Summary generation failed',
          error: true
        };
      }
    });

    const summaries = await Promise.all(summariesPromises);

    return NextResponse.json({
      success: true,
      summaries,
      totalProcessed: summaries.length,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Error fetching and summarizing vulnerabilities:', error);
    return NextResponse.json(
      { error: 'Failed to fetch and summarize vulnerabilities' },
      { status: 500 }
    );
  }
}