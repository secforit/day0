import { NextRequest, NextResponse } from 'next/server';
import { fetchCombinedVulnerabilities, type VulnerabilityData } from '@/lib/vulnerability-fetch';

function generateRSSFeed(vulnerabilities: VulnerabilityData[]): string {
  const now = new Date().toUTCString();
  const baseUrl = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000';
  
  const rssItems = vulnerabilities.map(vuln => `
    <item>
      <title><![CDATA[${vuln.cveId ? `${vuln.cveId}: ` : ''}${vuln.title}]]></title>
      <description><![CDATA[
        <p><strong>Severity:</strong> ${vuln.severity}</p>
        <p><strong>Source:</strong> ${vuln.source}</p>
        ${vuln.cvssScore ? `<p><strong>CVSS Score:</strong> ${vuln.cvssScore}</p>` : ''}
        ${vuln.vendor && vuln.product ? `<p><strong>Affected:</strong> ${vuln.vendor} ${vuln.product}</p>` : ''}
        ${vuln.dueDate ? `<p><strong>Remediation Due:</strong> ${new Date(vuln.dueDate).toLocaleDateString()}</p>` : ''}
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
    <description>Latest zero-day and critical vulnerabilities from official security sources (CISA KEV and NVD)</description>
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
    // Fetch recent vulnerabilities from both sources with proper filtering
    // CISA: 15 most recent actively exploited vulnerabilities
    // NVD: Last 30 days, CVSS >= 7.0 (High/Critical only)
    const vulnerabilities = await fetchCombinedVulnerabilities(15, 30, 7.0);
    
    if (vulnerabilities.length === 0) {
      console.warn('No vulnerabilities fetched for RSS feed');
    }
    
    const rssContent = generateRSSFeed(vulnerabilities);
    
    return new NextResponse(rssContent, {
      status: 200,
      headers: {
        'Content-Type': 'application/rss+xml; charset=utf-8',
        'Cache-Control': 'public, max-age=1800', // 30 minutes
      }
    });
  } catch (error) {
    console.error('Error generating RSS feed:', error);
    return new NextResponse('Error generating feed', { status: 500 });
  }
}