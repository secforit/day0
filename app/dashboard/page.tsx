import { refreshVulnerabilityFeed, getVulnerabilityStats } from '../actions/vulnerability-actions';
import Link from 'next/link';
import Footer from '../../components/Footer';
import type { Metadata } from 'next';
import { Shield, ArrowRight, AlertTriangle, Activity, TrendingUp, Clock, RefreshCw, Home, Brain } from 'lucide-react';

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
    case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/50';
    case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/50';
    case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/50';
    default: return 'bg-slate-700/20 text-slate-300 border-slate-700/50';
  }
}

function getSourceColor(source: string) {
  switch (source) {
    case 'CISA KEV': return 'bg-red-500/10 border-red-500/30';
    case 'NVD Recent': return 'bg-blue-500/10 border-blue-500/30';
    default: return 'bg-slate-700/10 border-slate-700/30';
  }
}

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
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
      />
      
      <div className="min-h-screen flex flex-col bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
        <div className="container mx-auto px-6 py-8 max-w-7xl flex-grow">
          {/* Breadcrumb navigation */}
          <nav aria-label="Breadcrumb" className="mb-6">
            <ol className="flex items-center space-x-2 text-sm text-slate-400">
              <li>
                <Link href="/" className="hover:text-red-400 transition-colors">
                  Home
                </Link>
              </li>
              <li aria-hidden="true">/</li>
              <li className="text-slate-200 font-medium">Dashboard</li>
            </ol>
          </nav>

          {/* Header */}
          <header className="mb-12">
            <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6">
              <div>
                <div className="flex items-center space-x-4 mb-4">
                  <div className="w-14 h-14 bg-gradient-to-br from-red-600 to-orange-600 rounded-xl flex items-center justify-center shadow-lg shadow-red-500/20">
                    <Activity className="w-8 h-8 text-white" />
                  </div>
                  <div>
                    <h1 className="text-4xl font-bold text-white mb-2">
                      Vulnerability Dashboard
                    </h1>
                    <p className="text-slate-400 text-lg">
                      Real-time monitoring and analytics for critical security threats
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="flex gap-3 flex-wrap">
                <Link 
                  href="/ai-summaries"
                  className="px-5 py-3 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-semibold transition-all duration-300 shadow-lg shadow-purple-500/20 hover:shadow-purple-500/40 inline-flex items-center space-x-2"
                  aria-label="View AI-powered vulnerability analysis"
                >
                  <Brain className="w-5 h-5" />
                  <span>AI Analysis</span>
                </Link>
                <Link 
                  href="/"
                  className="px-5 py-3 rounded-lg border border-slate-700 hover:border-slate-600 bg-slate-900 hover:bg-slate-800 text-white font-semibold transition-colors inline-flex items-center space-x-2"
                  aria-label="Return to home page"
                >
                  <Home className="w-5 h-5" />
                  <span>Home</span>
                </Link>
              </div>
            </div>
          </header>
        
          {/* Stats Cards */}
          <section aria-label="Vulnerability statistics" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
            {/* Total in Feed */}
            <div className="relative group">
              <div className="absolute inset-0 bg-gradient-to-br from-blue-600/20 to-cyan-600/20 rounded-xl blur-xl group-hover:blur-2xl transition-all opacity-50" />
              <div className="relative bg-slate-950 border border-slate-800 hover:border-blue-500/50 rounded-xl p-6 transition-all duration-300">
                <div className="flex items-center justify-between mb-4">
                  <div className="w-12 h-12 bg-gradient-to-br from-blue-600 to-cyan-600 rounded-lg flex items-center justify-center shadow-lg shadow-blue-500/20">
                    <Shield className="w-6 h-6 text-white" />
                  </div>
                  <TrendingUp className="w-5 h-5 text-blue-400" />
                </div>
                <h2 className="text-sm font-medium text-slate-400 uppercase tracking-wide mb-2">Total in Feed</h2>
                {stats.success ? (
                  <p className="text-4xl font-bold bg-gradient-to-r from-blue-500 to-cyan-500 bg-clip-text text-transparent" aria-label={`${stats.totalVulnerabilities} total vulnerabilities tracked`}>
                    {stats.totalVulnerabilities}
                  </p>
                ) : (
                  <p className="text-red-400 font-semibold text-sm">Error loading data</p>
                )}
                <p className="text-xs text-slate-500 mt-2">Tracked vulnerabilities</p>
              </div>
            </div>
          
            {/* CISA KEV Recent */}
            <div className="relative group">
              <div className="absolute inset-0 bg-gradient-to-br from-red-600/20 to-orange-600/20 rounded-xl blur-xl group-hover:blur-2xl transition-all opacity-50" />
              <div className="relative bg-slate-950 border border-slate-800 hover:border-red-500/50 rounded-xl p-6 transition-all duration-300">
                <div className="flex items-center justify-between mb-4">
                  <div className="w-12 h-12 bg-gradient-to-br from-red-600 to-orange-600 rounded-lg flex items-center justify-center shadow-lg shadow-red-500/20">
                    <AlertTriangle className="w-6 h-6 text-white" />
                  </div>
                  <span className="px-2 py-1 bg-red-500/20 text-red-300 text-xs font-bold rounded border border-red-500/30">
                    CRITICAL
                  </span>
                </div>
                <h2 className="text-sm font-medium text-slate-400 uppercase tracking-wide mb-2">CISA KEV Recent</h2>
                <p className="text-4xl font-bold bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent" aria-label={`${zeroDayVulns.filter(v => v.source === 'CISA KEV').length} actively exploited vulnerabilities`}>
                  {zeroDayVulns.filter(v => v.source === 'CISA KEV').length}
                </p>
                <p className="text-xs text-slate-500 mt-2">Actively exploited</p>
              </div>
            </div>
          
            {/* High Severity */}
            <div className="relative group">
              <div className="absolute inset-0 bg-gradient-to-br from-orange-600/20 to-yellow-600/20 rounded-xl blur-xl group-hover:blur-2xl transition-all opacity-50" />
              <div className="relative bg-slate-950 border border-slate-800 hover:border-orange-500/50 rounded-xl p-6 transition-all duration-300">
                <div className="flex items-center justify-between mb-4">
                  <div className="w-12 h-12 bg-gradient-to-br from-orange-600 to-yellow-600 rounded-lg flex items-center justify-center shadow-lg shadow-orange-500/20">
                    <TrendingUp className="w-6 h-6 text-white" />
                  </div>
                  <span className="px-2 py-1 bg-orange-500/20 text-orange-300 text-xs font-bold rounded border border-orange-500/30">
                    HIGH
                  </span>
                </div>
                <h2 className="text-sm font-medium text-slate-400 uppercase tracking-wide mb-2">High Severity</h2>
                <p className="text-4xl font-bold bg-gradient-to-r from-orange-500 to-yellow-500 bg-clip-text text-transparent">
                  {zeroDayVulns.filter(v => v.source === 'NVD Recent').length}
                </p>
                <p className="text-xs text-slate-500 mt-2">Recent high-risk CVEs</p>
              </div>
            </div>
          
            {/* RSS Feed */}
            <div className="relative group">
              <div className="absolute inset-0 bg-gradient-to-br from-green-600/20 to-emerald-600/20 rounded-xl blur-xl group-hover:blur-2xl transition-all opacity-50" />
              <div className="relative bg-slate-950 border border-slate-800 hover:border-green-500/50 rounded-xl p-6 transition-all duration-300">
                <div className="flex items-center justify-between mb-4">
                  <div className="w-12 h-12 bg-gradient-to-br from-green-600 to-emerald-600 rounded-lg flex items-center justify-center shadow-lg shadow-green-500/20">
                    <Clock className="w-6 h-6 text-white" />
                  </div>
                  <RefreshCw className="w-5 h-5 text-green-400" />
                </div>
                <h2 className="text-sm font-medium text-slate-400 uppercase tracking-wide mb-2">RSS Feed</h2>
                <div className="flex gap-2 mt-4">
                  <a 
                    href="/rss" 
                    className="flex-1 px-4 py-2 bg-gradient-to-r from-orange-600 to-orange-500 hover:from-orange-500 hover:to-orange-400 text-white text-sm font-semibold rounded-lg transition-all duration-300 text-center"
                    target="_blank"
                    aria-label="View RSS feed"
                  >
                    View Feed
                  </a>
                  <form action={handleRefresh} className="flex-1">
                    <button 
                      type="submit"
                      className="w-full px-4 py-2 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-500 hover:to-emerald-500 text-white text-sm font-semibold rounded-lg transition-all duration-300"
                      aria-label="Refresh vulnerability feed"
                    >
                      Refresh
                    </button>
                  </form>
                </div>
              </div>
            </div>
          </section>

          {/* Vulnerabilities Section */}
          <section aria-label="Recent vulnerabilities">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
              <div>
                <h2 className="text-3xl font-bold text-white flex items-center space-x-3 mb-2">
                  <div className="w-10 h-10 bg-gradient-to-br from-red-600 to-orange-600 rounded-lg flex items-center justify-center shadow-lg shadow-red-500/20">
                    <AlertTriangle className="w-6 h-6 text-white" />
                  </div>
                  <span>Recent Zero-Day & Critical Vulnerabilities</span>
                </h2>
                <p className="text-slate-400 ml-13">Last 30 days from trusted security sources</p>
              </div>
              <time className="text-sm text-slate-400 bg-slate-900/50 px-4 py-2 rounded-lg border border-slate-700">
                <Clock className="w-4 h-4 inline mr-2" />
                Updated: {new Date().toLocaleString('en-US', { 
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
                    className="group relative bg-slate-950 rounded-xl border border-slate-800 hover:border-slate-700 transition-all duration-300 overflow-hidden hover:bg-slate-900/50"
                    itemScope 
                    itemType="https://schema.org/TechArticle"
                  >
                    <div className="absolute inset-0 bg-gradient-to-br from-red-600/5 to-orange-600/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                    <div className="relative p-6">
                      {/* Header */}
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold border ${getSourceColor(vuln.source)} transition-colors`} itemProp="provider">
                            {vuln.source}
                          </span>
                          {vuln.source === 'CISA KEV' && (
                            <span className="bg-red-500/20 text-red-300 text-xs px-3 py-1 rounded-full font-bold border border-red-500/30 inline-flex items-center space-x-1">
                              <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                              <span>ACTIVELY EXPLOITED</span>
                            </span>
                          )}
                        </div>
                        <span className={`px-3 py-1 text-xs font-semibold rounded-full border ${getSeverityColor(vuln.severity)}`}>
                          {vuln.severity}
                          {vuln.cvssScore && ` (${vuln.cvssScore})`}
                        </span>
                      </div>
                    
                      {/* Title */}
                      <h3 className="text-lg font-bold text-white mb-3 leading-tight group-hover:text-transparent group-hover:bg-gradient-to-r group-hover:from-red-500 group-hover:to-orange-500 group-hover:bg-clip-text transition-all" itemProp="headline">
                        {vuln.cveId && <span className="text-red-400" itemProp="identifier">{vuln.cveId}: </span>}
                        {vuln.title}
                      </h3>
                    
                      {/* Description */}
                      <p className="text-slate-400 text-sm mb-4 leading-relaxed" itemProp="description">
                        {vuln.description.length > 150 
                          ? `${vuln.description.substring(0, 150)}...` 
                          : vuln.description}
                      </p>
                    
                      {/* Product Info */}
                      {(vuln.product || vuln.vendor) && (
                        <div className="mb-4 p-3 bg-slate-900/50 rounded-lg border border-slate-700">
                          <span className="text-xs font-medium text-slate-400 uppercase tracking-wide">Affected Product</span>
                          <p className="text-sm font-semibold text-slate-200 mt-1" itemProp="about">
                            {vuln.vendor && vuln.product ? `${vuln.vendor} ${vuln.product}` : vuln.vendor || vuln.product}
                          </p>
                        </div>
                      )}
                    
                      {/* Footer */}
                      <div className="flex justify-between items-center pt-4 border-t border-slate-700">
                        <div className="flex flex-col gap-1">
                          <time dateTime={vuln.published} itemProp="datePublished" className="text-xs text-slate-500">
                            Published: {new Date(vuln.published).toLocaleDateString('en-US', { 
                              year: 'numeric', 
                              month: 'short', 
                              day: 'numeric' 
                            })}
                          </time>
                          {vuln.source === 'CISA KEV' && vuln.dueDate && (
                            <time dateTime={vuln.dueDate} className="text-xs text-red-400 font-semibold">
                              Due: {new Date(vuln.dueDate).toLocaleDateString('en-US', { 
                                year: 'numeric', 
                                month: 'short', 
                                day: 'numeric' 
                              })}
                            </time>
                          )}
                        </div>
                        <div className="flex gap-2">
                          <a 
                            href={vuln.link}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-4 py-2 bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white text-sm font-semibold rounded-lg transition-all duration-300 inline-flex items-center space-x-1"
                            itemProp="url"
                            aria-label={`View full details for ${vuln.cveId || vuln.title}`}
                          >
                            <span>Details</span>
                            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                          </a>
                          {vuln.cveId && (
                            <a 
                              href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cveId}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="px-4 py-2 border border-slate-700 hover:border-slate-600 bg-slate-900 hover:bg-slate-800 text-white text-sm font-semibold rounded-lg transition-colors"
                              aria-label={`View ${vuln.cveId} on MITRE CVE`}
                            >
                              MITRE
                            </a>
                          )}
                        </div>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            ) : (
              <div className="bg-slate-950 rounded-xl border border-slate-800 p-16 text-center">
                <div className="inline-flex items-center justify-center w-20 h-20 bg-slate-900 rounded-full mb-6 border border-slate-700">
                  <AlertTriangle className="w-12 h-12 text-slate-600" />
                </div>
                <h3 className="text-2xl font-bold text-white mb-3">No Recent Zero-Day Vulnerabilities</h3>
                <p className="text-slate-400 max-w-md mx-auto mb-6">Either there are no recent critical vulnerabilities, or the feeds are temporarily unavailable.</p>
                <div className="flex justify-center gap-4">
                  <Link 
                    href="/"
                    className="px-6 py-3 rounded-lg bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white font-semibold transition-all duration-300"
                  >
                    Back to Home
                  </Link>
                  <Link 
                    href="/ai-summaries"
                    className="px-6 py-3 rounded-lg border border-slate-700 hover:border-slate-600 bg-slate-900 hover:bg-slate-800 text-white font-semibold transition-colors"
                  >
                    View AI Analysis
                  </Link>
                </div>
              </div>
            )}
          </section>

          {/* Information Section */}
          <section aria-label="Dashboard information" className="mt-12 bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
            <div className="bg-gradient-to-r from-red-600/20 to-orange-600/20 border-b border-slate-800 px-8 py-6">
              <h2 className="text-2xl font-bold text-white flex items-center space-x-3">
                <Shield className="w-6 h-6 text-red-500" />
                <span>About This Dashboard</span>
              </h2>
            </div>
            <div className="p-8">
              <div className="space-y-4 text-sm">
                <div className="flex items-start space-x-3">
                  <span className="w-2 h-2 bg-red-500 rounded-full mt-2 flex-shrink-0" aria-hidden="true"></span>
                  <p className="text-slate-300 leading-relaxed">
                    <strong className="text-white">CISA KEV:</strong> Known Exploited Vulnerabilities from CISA - actively being exploited in the wild and requiring immediate remediation
                  </p>
                </div>
                <div className="flex items-start space-x-3">
                  <span className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0" aria-hidden="true"></span>
                  <p className="text-slate-300 leading-relaxed">
                    <strong className="text-white">NVD Recent:</strong> Recently published high/critical severity CVEs from the National Vulnerability Database with CVSS v3.1 scoring
                  </p>
                </div>
                <div className="flex items-start space-x-3">
                  <span className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0" aria-hidden="true"></span>
                  <p className="text-slate-300 leading-relaxed">
                    <strong className="text-white">Update Frequency:</strong> Data is cached for 30 minutes and refreshed automatically to ensure timely security intelligence
                  </p>
                </div>
                <div className="flex items-start space-x-3">
                  <span className="w-2 h-2 bg-purple-500 rounded-full mt-2 flex-shrink-0" aria-hidden="true"></span>
                  <p className="text-slate-300 leading-relaxed">
                    <strong className="text-white">Sources:</strong>{' '}
                    <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" className="text-red-400 hover:text-red-300 hover:underline transition-colors">
                      CISA KEV Catalog
                    </a>
                    {', '}
                    <a href="https://nvd.nist.gov/" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300 hover:underline transition-colors">
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