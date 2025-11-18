import { NextRequest, NextResponse } from 'next/server';

interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: string;
  published: string;
  updated: string;
  source: string;
  link: string;
  cveId?: string;
  cvssScore?: number;
}

// Official sources for vulnerability data
const VULNERABILITY_SOURCES = [
  {
    name: 'CISA KEV',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    type: 'json'
  },
  {
    name: 'NVD Recent',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&startIndex=0',
    type: 'json'
  }
];

async function fetchCISAVulnerabilities(): Promise<Vulnerability[]> {
  try {
    const response = await fetch(VULNERABILITY_SOURCES[0].url, {
      next: { revalidate: 3600 } // Cache for 1 hour
    });
    
    if (!response.ok) throw new Error('Failed to fetch CISA data');
    
    const data = await response.json();
    
    return data.vulnerabilities?.slice(0, 10).map((vuln: any) => ({
      id: vuln.cveID || `cisa-${Date.now()}-${Math.random()}`,
      title: `${vuln.cveID}: ${vuln.vulnerabilityName}`,
      description: `${vuln.shortDescription} | Product: ${vuln.product} | Vendor: ${vuln.vendorProject}`,
      severity: 'Critical',
      published: vuln.dateAdded,
      updated: vuln.dateAdded,
      source: 'CISA Known Exploited Vulnerabilities',
      link: `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`,
      cveId: vuln.cveID
    })) || [];
  } catch (error) {
    console.error('Error fetching CISA vulnerabilities:', error);
    return [];
  }
}

async function fetchNVDVulnerabilities(): Promise<Vulnerability[]> {
  try {
    const response = await fetch(VULNERABILITY_SOURCES[1].url, {
      next: { revalidate: 3600 },
      headers: {
        'User-Agent': 'ZeroDayRSSFeed/1.0'
      }
    });
    
    if (!response.ok) throw new Error('Failed to fetch NVD data');
    
    const data = await response.json();
    
    return data.vulnerabilities?.slice(0, 10).map((item: any) => {
      const vuln = item.cve;
      const description = vuln.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available';
      const cvssScore = vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                       vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore;
      
      return {
        id: vuln.id,
        title: `${vuln.id}: ${description.substring(0, 100)}...`,
        description: description,
        severity: cvssScore >= 9 ? 'Critical' : cvssScore >= 7 ? 'High' : cvssScore >= 4 ? 'Medium' : 'Low',
        published: vuln.published,
        updated: vuln.lastModified,
        source: 'National Vulnerability Database',
        link: `https://nvd.nist.gov/vuln/detail/${vuln.id}`,
        cveId: vuln.id,
        cvssScore: cvssScore
      };
    }) || [];
  } catch (error) {
    console.error('Error fetching NVD vulnerabilities:', error);
    return [];
  }
}

async function getAllVulnerabilities(): Promise<Vulnerability[]> {
  const [cisaVulns, nvdVulns] = await Promise.all([
    fetchCISAVulnerabilities(),
    fetchNVDVulnerabilities()
  ]);
  
  const allVulns = [...cisaVulns, ...nvdVulns];
  return allVulns.sort((a, b) => new Date(b.published).getTime() - new Date(a.published).getTime());
}

function generateRSSFeed(vulnerabilities: Vulnerability[]): string {
  const now = new Date().toUTCString();
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000';
  
  const rssItems = vulnerabilities.map(vuln => `
    <item>
      <title><![CDATA[${vuln.title}]]></title>
      <description><![CDATA[
        <p><strong>Severity:</strong> ${vuln.severity}</p>
        <p><strong>Source:</strong> ${vuln.source}</p>
        ${vuln.cvssScore ? `<p><strong>CVSS Score:</strong> ${vuln.cvssScore}</p>` : ''}
        <p><strong>Description:</strong></p>
        <p>${vuln.description}</p>
        <p><a href="${vuln.link}" target="_blank">View Full Details</a></p>
      ]]></description>
      <link>${vuln.link}</link>
      <guid isPermaLink="false">${vuln.id}</guid>
      <pubDate>${new Date(vuln.published).toUTCString()}</pubDate>
      <category>${vuln.severity}</category>
      <source url="${vuln.link}">${vuln.source}</source>
    </item>
  `).join('');

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>Zero-Day Vulnerabilities Feed</title>
    <description>Latest zero-day and critical vulnerabilities from official security sources</description>
    <link>${baseUrl}/rss</link>
    <atom:link href="${baseUrl}/rss" rel="self" type="application/rss+xml" />
    <language>en-us</language>
    <lastBuildDate>${now}</lastBuildDate>
    <pubDate>${now}</pubDate>
    <ttl>60</ttl>
    ${rssItems}
  </channel>
</rss>`;
}

export async function GET(request: NextRequest) {
  try {
    const vulnerabilities = await getAllVulnerabilities();
    const rssContent = generateRSSFeed(vulnerabilities);
    
    return new NextResponse(rssContent, {
      status: 200,
      headers: {
        'Content-Type': 'application/rss+xml; charset=utf-8',
        'Cache-Control': 'public, max-age=3600',
      }
    });
  } catch (error) {
    console.error('Error generating RSS feed:', error);
    return new NextResponse('Error generating feed', { status: 500 });
  }
}