import { refreshVulnerabilityFeed, getVulnerabilityStats } from '../actions/vulnerability-actions';
import Link from 'next/link';
import Footer from '../../components/Footer';
import type { Metadata } from 'next';

// SEO Metadata for Dashboard
export const metadata: Metadata = {
  title: "Vulnerability Dashboard | Real-Time CVE Statistics & Monitoring",
  description: "Comprehensive vulnerability dashboard displaying real-time statistics from CISA KEV and NVD. Monitor critical and high-severity CVEs, track actively exploited vulnerabilities, and access detailed threat intelligence with CVSS scoring.",
  keywords: [
    "vulnerability dashboard",
    "CVE statistics",
    "real-time monitoring",
    "CISA KEV dashboard",
    "security metrics",
    "threat intelligence dashboard",
    "vulnerability analytics",
    "security operations center",
    "SOC dashboard",
    "cyber threat monitoring"
  ],
  openGraph: {
    title: "Vulnerability Dashboard | Real-Time CVE Statistics",
    description: "Monitor critical vulnerabilities and CVEs with real-time statistics from trusted security sources.",
    url: "https://secforit.ro/dashboard",
    type: "website",
  },
  alternates: {
    canonical: "https://secforit.ro/dashboard"
  }
};

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
  product?: string;
  vendor?: string;
  dueDate?: string;
}

async function fetchZeroDayVulnerabilities(): Promise<Vulnerability[]> {
  try {
    const cisaResponse = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
      next: { revalidate: 1800 }
    });
    
    let zeroDayVulns: Vulnerability[] = [];
    
    if (cisaResponse.ok) {
      const cisaData = await cisaResponse.json();
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      
      const recentCisaVulns = cisaData.vulnerabilities
        ?.filter((vuln: any) => new Date(vuln.dateAdded) > thirtyDaysAgo)
        .slice(0, 15)
        .map((vuln: any) => ({
          id: vuln.cveID || `cisa-${Date.now()}-${Math.random()}`,
          title: vuln.vulnerabilityName || 'Unknown Vulnerability',
          description: vuln.shortDescription || 'No description available',
          severity: 'Critical',
          published: vuln.dateAdded,
          updated: vuln.dateAdded,
          source: 'CISA KEV',
          link: `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`,
          cveId: vuln.cveID,
          product: vuln.product,
          vendor: vuln.vendorProject,
          dueDate: vuln.dueDate
        })) || [];
      
      zeroDayVulns = [...zeroDayVulns, ...recentCisaVulns];
    }

    try {
      const nvdResponse = await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10&startIndex=0', {
        next: { revalidate: 1800 },
        headers: { 'User-Agent': 'ZeroDayDashboard/1.0' }
      });
      
      if (nvdResponse.ok) {
        const nvdData = await nvdResponse.json();
        const recentHighSeverity = nvdData.vulnerabilities
          ?.filter((item: any) => {
            const vuln = item.cve;
            const cvssScore = vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                             vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore;
            
            const publishedDate = new Date(vuln.published);
            const sevenDaysAgo = new Date();
            sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
            
            return cvssScore >= 7.0 && publishedDate > sevenDaysAgo;
          })
          .slice(0, 8)
          .map((item: any) => {
            const vuln = item.cve;
            const description = vuln.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available';
            const cvssScore = vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                             vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore;
            
            return {
              id: vuln.id,
              title: vuln.id,
              description: description,
              severity: cvssScore >= 9 ? 'Critical' : 'High',
              published: vuln.published,
              updated: vuln.lastModified,
              source: 'NVD Recent',
              link: `https://nvd.nist.gov/vuln/detail/${vuln.id}`,
              cveId: vuln.id,
              cvssScore: cvssScore
            };
          }) || [];
        
        zeroDayVulns = [...zeroDayVulns, ...recentHighSeverity];
      }
    } catch (nvdError) {
      console.error('NVD fetch failed:', nvdError);
    }

    return zeroDayVulns.sort((a, b) => new Date(b.published).getTime() - new Date(a.published).getTime());
    
  } catch (error) {
    console.error('Error fetching zero-day vulnerabilities:', error);
    return [];
  }
}

function getSeverityColor(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical': return 'status-critical';
    case 'high': return 'status-high';
    case 'medium': return 'status-medium';
    default: return 'bg-gray-100 text-gray-800 border-gray-300';
  }
}

function getSourceBadgeColor(source: string) {
  switch (source) {
    case 'CISA KEV': return 'bg-red-500';
    case 'NVD Recent': return 'bg-blue-500';
    default: return 'bg-gray-500';
  }
}

// Structured Data for Dashboard
function generateDashboardStructuredData(vulnerabilities: Vulnerability[], stats: any) {
  return {
    "@context": "https://schema.org",
    "@type": "WebPage",
    "name": "Vulnerability Dashboard",
    "description": "Real-time vulnerability monitoring dashboard with CVE statistics",
    "url": "https://secforit.ro/dashboard",
    "breadcrumb": {
      "@type": "BreadcrumbList",
      "itemListElement": [
        {
          "@type": "ListItem",
          "position": 1,
          "name": "Home",
          "item": "https://secforit.ro"
        },
        {
          "@type": "ListItem",
          "position": 2,
          "name": "Dashboard",
          "item": "https://secforit.ro/dashboard"
        }
      ]
    },
    "mainEntity": {
      "@type": "Dataset",
      "name": "Vulnerability Statistics",
      "description": "Real-time vulnerability data from CISA KEV and NVD",
      "distribution": [
        {
          "@type": "DataDownload",
          "encodingFormat": "application/rss+xml",
          "contentUrl": "https://secforit.ro/rss"
        }
      ]
    }
  };
}

export default async function Dashboard() {
  const stats = await getVulnerabilityStats();
  const zeroDayVulns = await fetchZeroDayVulnerabilities();
  const structuredData = generateDashboardStructuredData(zeroDayVulns, stats);
  
  async function handleRefresh() {
    'use server'
    await refreshVulnerabilityFeed();
  }
  
  return (
    <>
      {/* Structured Data */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
      />
      
      <div className="min-h-screen flex flex-col bg-gradient-to-br from-gray-50 to-gray-100">
        <div className="container mx-auto p-6 max-w-7xl flex-grow">
          {/* Header with breadcrumb navigation */}
          <nav aria-label="Breadcrumb" className="mb-4">
            <ol className="flex items-center space-x-2 text-sm text-gray-600">
              <li>
                <Link href="/" className="hover:text-blue-600 transition-colors">
                  Home
                </Link>
              </li>
              <li aria-hidden="true">/</li>
              <li className="text-gray-900 font-medium">Dashboard</li>
            </ol>
          </nav>

          <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
            <header>
              <h1 className="text-4xl font-bold text-gray-900 mb-2 flex items-center space-x-3">
                <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg">
                  <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                </div>
                <span>Vulnerability Dashboard</span>
              </h1>
              <p className="text-gray-600">Real-time zero-day and critical vulnerability monitoring with comprehensive statistics</p>
            </header>
            <div className="flex gap-3">
              <Link 
                href="/ai-summaries"
                className="bg-purple-600 text-white px-5 py-2.5 rounded-lg font-medium hover:bg-purple-700 transition-colors duration-200 shadow-sm inline-flex items-center space-x-2"
                aria-label="View AI-powered vulnerability analysis"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
                <span>AI Analysis</span>
              </Link>
              <Link 
                href="/"
                className="btn-secondary"
                aria-label="Return to home page"
              >
                Back to Home
              </Link>
            </div>
          </div>
        
          {/* Stats Cards with semantic HTML */}
          <section aria-label="Vulnerability statistics" className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-white p-6 rounded-xl shadow-md border border-gray-200 card-hover">
              <div className="flex items-center justify-between mb-2">
                <h2 className="text-sm font-medium text-gray-500 uppercase tracking-wide">Total in Feed</h2>
                <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center" aria-hidden="true">
                  <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
              </div>
              {stats.success ? (
                <p className="text-3xl font-bold text-blue-600" aria-label={`${stats.totalVulnerabilities} total vulnerabilities tracked`}>
                  {stats.totalVulnerabilities}
                </p>
              ) : (
                <p className="text-red-500 font-semibold">Error loading data</p>
              )}
            </div>
          
            <div className="bg-white p-6 rounded-xl shadow-md border border-gray-200 card-hover">
              <div className="flex items-center justify-between mb-2">
                <h2 className="text-sm font-medium text-gray-500 uppercase tracking-wide">CISA KEV Recent</h2>
                <div className="w-10 h-10 bg-red-100 rounded-lg flex items-center justify-center" aria-hidden="true">
                  <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
              </div>
              <p className="text-3xl font-bold text-red-600" aria-label={`${zeroDayVulns.filter(v => v.source === 'CISA KEV').length} actively exploited vulnerabilities`}>
                {zeroDayVulns.filter(v => v.source === 'CISA KEV').length}
              </p>
            </div>
          
            <div className="bg-white p-6 rounded-xl shadow-md border border-gray-200 card-hover">
              <div className="flex items-center justify-between mb-2">
                <h2 className="text-sm font-medium text-gray-500 uppercase tracking-wide">High Severity</h2>
                <div className="w-10 h-10 bg-orange-100 rounded-lg flex items-center justify-center" aria-hidden="true">
                  <svg className="w-6 h-6 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
              </div>
              <p className="text-3xl font-bold text-orange-600">
                {zeroDayVulns.filter(v => v.source === 'NVD Recent').length}
              </p>
            </div>
          
            <div className="bg-white p-6 rounded-xl shadow-md border border-gray-200 card-hover">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-medium text-gray-500 uppercase tracking-wide">RSS Feed</h2>
                <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center" aria-hidden="true">
                  <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 5c7.18 0 13 5.82 13 13M6 11a7 7 0 017 7m-6 0a1 1 0 11-2 0 1 1 0 012 0z" />
                  </svg>
                </div>
              </div>
              <div className="flex gap-2">
                <a 
                  href="/rss" 
                  className="bg-orange-500 text-white px-3 py-1.5 rounded-lg text-sm hover:bg-orange-600 transition-colors font-medium"
                  target="_blank"
                  aria-label="View RSS feed"
                >
                  View
                </a>
                <form action={handleRefresh} className="inline">
                  <button 
                    type="submit"
                    className="btn-success text-sm px-3 py-1.5"
                    aria-label="Refresh vulnerability feed"
                  >
                    Refresh
                  </button>
                </form>
              </div>
            </div>
          </section>

          {/* Vulnerabilities Section */}
          <section aria-label="Recent vulnerabilities">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
              <div>
                <h2 className="text-2xl font-bold text-gray-900 flex items-center space-x-2">
                  <span className="inline-flex items-center justify-center w-8 h-8 bg-red-100 rounded-lg">
                    <svg className="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                  </span>
                  <span>Recent Zero-Day & Critical Vulnerabilities</span>
                </h2>
                <p className="text-gray-600 mt-1">Last 30 days from trusted security sources</p>
              </div>
              <time className="text-sm text-gray-500 bg-white px-4 py-2 rounded-lg border border-gray-200">
                Last updated: {new Date().toLocaleString('en-US', { 
                  month: 'short', 
                  day: 'numeric', 
                  hour: '2-digit', 
                  minute: '2-digit' 
                })}
              </time>
            </div>
          
            {zeroDayVulns.length > 0 ? (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {zeroDayVulns.map((vuln) => (
                  <article 
                    key={vuln.id} 
                    className="bg-white rounded-xl shadow-md border border-gray-200 card-hover overflow-hidden"
                    itemScope 
                    itemType="https://schema.org/TechArticle"
                  >
                    <div className="p-6">
                      {/* Header */}
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center gap-2">
                          <span className={`w-3 h-3 rounded-full ${getSourceBadgeColor(vuln.source)}`} aria-hidden="true"></span>
                          <span className="text-sm font-semibold text-gray-700" itemProp="provider">{vuln.source}</span>
                          {vuln.source === 'CISA KEV' && (
                            <span className="bg-red-100 text-red-700 text-xs px-2 py-1 rounded-md font-bold">
                              ACTIVELY EXPLOITED
                            </span>
                          )}
                        </div>
                        <span className={`px-3 py-1 text-xs font-semibold rounded-full border ${getSeverityColor(vuln.severity)}`}>
                          {vuln.severity}
                          {vuln.cvssScore && ` (${vuln.cvssScore})`}
                        </span>
                      </div>
                    
                      {/* Title */}
                      <h3 className="text-lg font-bold text-gray-900 mb-3" itemProp="headline">
                        {vuln.cveId && <span className="text-blue-600" itemProp="identifier">{vuln.cveId}: </span>}
                        {vuln.title}
                      </h3>
                    
                      {/* Description */}
                      <p className="text-gray-600 text-sm mb-4 leading-relaxed" itemProp="description">
                        {vuln.description.length > 150 
                          ? `${vuln.description.substring(0, 150)}...` 
                          : vuln.description}
                      </p>
                    
                      {/* Product Info */}
                      {(vuln.product || vuln.vendor) && (
                        <div className="mb-4 p-3 bg-gray-50 rounded-lg border border-gray-200">
                          <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">Affected Product</span>
                          <p className="text-sm font-semibold text-gray-800 mt-1" itemProp="about">
                            {vuln.vendor && vuln.product ? `${vuln.vendor} ${vuln.product}` : vuln.vendor || vuln.product}
                          </p>
                        </div>
                      )}
                    
                      {/* Dates */}
                      <div className="flex justify-between items-center text-sm mb-4 pb-4 border-b border-gray-200">
                        <time dateTime={vuln.published} itemProp="datePublished" className="text-gray-600">
                          <span className="font-medium">Published:</span> {new Date(vuln.published).toLocaleDateString('en-US', { 
                            year: 'numeric', 
                            month: 'short', 
                            day: 'numeric' 
                          })}
                        </time>
                        {vuln.source === 'CISA KEV' && vuln.dueDate && (
                          <time dateTime={vuln.dueDate} className="text-red-600 font-semibold">
                            Due: {new Date(vuln.dueDate).toLocaleDateString('en-US', { 
                              year: 'numeric', 
                              month: 'short', 
                              day: 'numeric' 
                            })}
                          </time>
                        )}
                      </div>
                    
                      {/* Action Buttons */}
                      <div className="flex gap-2">
                        <a 
                          href={vuln.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="btn-primary text-sm flex-1 text-center"
                          itemProp="url"
                          aria-label={`View full details for ${vuln.cveId || vuln.title}`}
                        >
                          View Details
                        </a>
                        {vuln.cveId && (
                          <a 
                            href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cveId}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn-secondary text-sm"
                            aria-label={`View ${vuln.cveId} on MITRE CVE`}
                          >
                            MITRE CVE
                          </a>
                        )}
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            ) : (
              <div className="bg-white rounded-xl shadow-md border border-gray-200 p-12 text-center">
                <div className="inline-flex items-center justify-center w-20 h-20 bg-gray-100 rounded-full mb-6">
                  <svg className="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-gray-800 mb-3">No Recent Zero-Day Vulnerabilities</h3>
                <p className="text-gray-600 max-w-md mx-auto">Either there are no recent critical vulnerabilities, or the feeds are temporarily unavailable.</p>
              </div>
            )}
          </section>

          {/* Information Section */}
          <section aria-label="Dashboard information" className="mt-8 bg-white rounded-xl shadow-md border border-gray-200 overflow-hidden">
            <div className="bg-gradient-to-r from-blue-600 to-blue-700 px-6 py-4">
              <h2 className="text-lg font-bold text-white flex items-center space-x-2">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>About This Dashboard</span>
              </h2>
            </div>
            <div className="p-6">
              <div className="space-y-4 text-sm">
                <div className="flex items-start space-x-3">
                  <span className="w-2 h-2 bg-blue-600 rounded-full mt-1.5 flex-shrink-0" aria-hidden="true"></span>
                  <p className="text-gray-700">
                    <strong className="text-gray-900">CISA KEV:</strong> Known Exploited Vulnerabilities from CISA - actively being exploited in the wild and requiring immediate remediation
                  </p>
                </div>
                <div className="flex items-start space-x-3">
                  <span className="w-2 h-2 bg-blue-600 rounded-full mt-1.5 flex-shrink-0" aria-hidden="true"></span>
                  <p className="text-gray-700">
                    <strong className="text-gray-900">NVD Recent:</strong> Recently published high/critical severity CVEs from the National Vulnerability Database with CVSS v3.1 scoring
                  </p>
                </div>
                <div className="flex items-start space-x-3">
                  <span className="w-2 h-2 bg-blue-600 rounded-full mt-1.5 flex-shrink-0" aria-hidden="true"></span>
                  <p className="text-gray-700">
                    <strong className="text-gray-900">Update Frequency:</strong> Data is cached for 30 minutes and refreshed automatically to ensure timely security intelligence
                  </p>
                </div>
                <div className="flex items-start space-x-3">
                  <span className="w-2 h-2 bg-blue-600 rounded-full mt-1.5 flex-shrink-0" aria-hidden="true"></span>
                  <p className="text-gray-700">
                    <strong className="text-gray-900">Sources:</strong>{' '}
                    <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:text-blue-800 hover:underline">
                      CISA KEV Catalog
                    </a>
                    {', '}
                    <a href="https://nvd.nist.gov/" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:text-blue-800 hover:underline">
                      NVD API
                    </a>
                  </p>
                </div>
              </div>
            </div>
          </section>
        </div>

        <Footer />
      </div>
    </>
  );
}