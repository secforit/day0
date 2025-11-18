import Link from 'next/link';
import Footer from '../components/Footer';
import type { Metadata } from 'next';
import { Shield, ArrowRight, AlertTriangle, Bell, Brain, CheckCircle } from 'lucide-react';

// SEO Metadata for Home Page
export const metadata: Metadata = {
  title: "Home | Real-Time Zero-Day Vulnerability & CVE Tracker",
  description: "Monitor critical zero-day vulnerabilities and CVEs in real-time from CISA KEV and National Vulnerability Database. \n Instant security alerts, CVSS scores, and vulnerability intelligence for proactive threat management.",
  keywords: [
    "zero-day tracker",
    "CVE monitoring",
    "CISA KEV catalog",
    "NVD vulnerabilities",
    "real-time security alerts",
    "vulnerability intelligence",
    "cyber threat monitoring",
    "exploit tracking",
    "security dashboard",
    "CVSS scores"
  ],
  openGraph: {
    title: "Zero-Day Vulnerability Tracker | Real-Time CVE Monitoring",
    description: "Professional platform for tracking zero-day vulnerabilities from CISA KEV and NVD with real-time updates and security intelligence.",
    url: "https://secforit.ro",
    type: "website",
    images: [
      {
        url: "/og-home.png",
        width: 1200,
        height: 630,
        alt: "Zero-Day Vulnerability Tracker Home"
      }
    ]
  },
  twitter: {
    card: "summary_large_image",
    title: "Zero-Day Vulnerability Tracker | Real-Time CVE Monitoring",
    description: "Track critical vulnerabilities from CISA KEV and NVD with real-time updates.",
  },
  alternates: {
    canonical: "https://secforit.ro"
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
}

async function fetchLatestVulnerabilities(): Promise<Vulnerability[]> {
  try {
    // Fetch CISA KEV data
    const cisaResponse = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
      next: { revalidate: 3600 }
    });
    
    let vulnerabilities: Vulnerability[] = [];
    
    if (cisaResponse.ok) {
      const cisaData = await cisaResponse.json();
      const cisaVulns = cisaData.vulnerabilities?.slice(0, 8).map((vuln: any) => ({
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
        vendor: vuln.vendorProject
      })) || [];
      
      vulnerabilities = [...vulnerabilities, ...cisaVulns];
    }

    // Fetch recent NVD data
    try {
      const nvdResponse = await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=6&startIndex=0', {
        next: { revalidate: 3600 },
        headers: { 'User-Agent': 'ZeroDayRSSFeed/1.0' }
      });
      
      if (nvdResponse.ok) {
        const nvdData = await nvdResponse.json();
        const nvdVulns = nvdData.vulnerabilities?.slice(0, 6).map((item: any) => {
          const vuln = item.cve;
          const description = vuln.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available';
          const cvssScore = vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                           vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore;
          
          return {
            id: vuln.id,
            title: vuln.id,
            description: description,
            severity: cvssScore >= 9 ? 'Critical' : cvssScore >= 7 ? 'High' : cvssScore >= 4 ? 'Medium' : 'Low',
            published: vuln.published,
            updated: vuln.lastModified,
            source: 'NVD',
            link: `https://nvd.nist.gov/vuln/detail/${vuln.id}`,
            cveId: vuln.id,
            cvssScore: cvssScore
          };
        }) || [];
        
        vulnerabilities = [...vulnerabilities, ...nvdVulns];
      }
    } catch (nvdError) {
      console.error('NVD fetch failed:', nvdError);
    }

    return vulnerabilities.sort((a, b) => new Date(b.published).getTime() - new Date(a.published).getTime());
    
  } catch (error) {
    console.error('Error fetching vulnerabilities:', error);
    return [];
  }
}

function getSeverityColor(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical': return 'bg-red-500/20 text-red-300 border-red-500/50';
    case 'high': return 'bg-orange-500/20 text-orange-300 border-orange-500/50';
    case 'medium': return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/50';
    case 'low': return 'bg-green-500/20 text-green-300 border-green-500/50';
    default: return 'bg-slate-700/20 text-slate-300 border-slate-700/50';
  }
}

function getSourceColor(source: string) {
  switch (source) {
    case 'CISA KEV': return 'bg-red-500/10 border-red-500/30';
    case 'NVD': return 'bg-blue-500/10 border-blue-500/30';
    default: return 'bg-slate-700/10 border-slate-700/30';
  }
}

// Structured Data (JSON-LD) for SEO
function generateStructuredData(vulnerabilities: Vulnerability[]) {
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebSite",
        "@id": "https://secforit.ro/#website",
        "url": "https://secforit.ro",
        "name": "Zero-Day Vulnerability Tracker",
        "description": "Real-time CVE monitoring from CISA KEV and National Vulnerability Database",
        "publisher": {
          "@id": "https://secforit.ro/#organization"
        },
        "inLanguage": "en-US"
      },
      {
        "@type": "Organization",
        "@id": "https://secforit.ro/#organization",
        "name": "SECFORIT SRL",
        "url": "https://secforit.ro",
        "logo": {
          "@type": "ImageObject",
          "url": "https://secforit.ro/logo.png",
          "width": 512,
          "height": 512
        },
        "founder": {
          "@type": "Person",
          "name": "Lisman Razvan"
        }
      }
    ]
  };
}

export default async function Home() {
  const vulnerabilities = await fetchLatestVulnerabilities();
  const structuredData = generateStructuredData(vulnerabilities);
  
  return (
    <>
      {/* Structured Data */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
      />
      
      <div className="min-h-screen bg-black text-white overflow-hidden">
        {/* Animated background grid */}
        <div className="fixed inset-0 overflow-hidden pointer-events-none">
          <div className="absolute inset-0 bg-gradient-to-b from-slate-950 via-black to-slate-950" />
          <svg className="absolute inset-0 w-full h-full opacity-10">
            <defs>
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgb(148, 163, 184)" strokeWidth="0.5"/>
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid)" />
          </svg>
        </div>

        <div className="relative max-w-7xl mx-auto px-6 py-16">
          {/* Hero Section */}
          <header className="text-center mb-20">
            <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-red-500 to-orange-500 rounded-2xl mb-6 shadow-2xl shadow-red-500/30">
              <Shield className="w-12 h-12 text-white" />
            </div>
            <h1 className="text-6xl font-bold mb-6 bg-gradient-to-r from-red-500 via-orange-500 to-red-500 bg-clip-text text-transparent">
              Zero-Day Vulnerability Tracker
            </h1>
            <p className="text-xl text-slate-400 mb-10 max-w-3xl mx-auto leading-relaxed">
              Real-time CVE monitoring from <strong className="text-red-400">CISA KEV</strong> and <strong className="text-blue-400">National Vulnerability Database</strong>.
              Instant security alerts and threat intelligence.
            </p>
            
            {/* Navigation with descriptive text for SEO */}
            <nav aria-label="Main navigation" className="flex flex-wrap justify-center gap-4 mb-12">
              <Link 
                href="/dashboard"
                className="group px-8 py-4 rounded-lg bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white font-semibold transition-all duration-300 shadow-lg shadow-red-500/20 hover:shadow-red-500/40 inline-flex items-center space-x-2"
                aria-label="View vulnerability dashboard with real-time statistics"
              >
                <span>Dashboard</span>
                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </Link>
              <Link 
                href="/ai-summaries"
                className="px-8 py-4 rounded-lg border border-purple-500/30 bg-purple-500/10 hover:bg-purple-500/20 text-white font-semibold transition-colors inline-flex items-center space-x-2"
                aria-label="View AI-powered vulnerability analysis and threat intelligence"
              >
                <Brain className="w-5 h-5" />
                <span>AI Analysis</span>
              </Link>
              <a 
                href="/rss"
                target="_blank"
                rel="noopener noreferrer"
                className="px-8 py-4 rounded-lg border border-slate-700 hover:border-slate-600 bg-slate-900 hover:bg-slate-800 text-white font-semibold transition-colors inline-flex items-center space-x-2"
                aria-label="Subscribe to RSS feed for vulnerability updates"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 5c7.18 0 13 5.82 13 13M6 11a7 7 0 017 7m-6 0a1 1 0 11-2 0 1 1 0 012 0z" />
                </svg>
                <span>RSS Feed</span>
              </a>
            </nav>
          </header>

          {vulnerabilities.length > 0 ? (
            <>
              {/* Stats Bar with semantic HTML */}
              <section aria-label="Vulnerability statistics" className="mb-16 bg-slate-950 rounded-xl border border-slate-800 p-8">
                <div className="flex flex-wrap justify-center items-center gap-12 text-center">
                  <div className="flex-1 min-w-[180px]">
                    <p className="text-sm font-medium text-slate-500 uppercase tracking-widest mb-2">CISA KEV</p>
                    <p className="text-4xl font-bold bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">
                      {vulnerabilities.filter(v => v.source === 'CISA KEV').length}
                    </p>
                  </div>
                  <div className="h-12 w-px bg-slate-700" aria-hidden="true"></div>
                  <div className="flex-1 min-w-[180px]">
                    <p className="text-sm font-medium text-slate-500 uppercase tracking-widest mb-2">NVD Recent</p>
                    <p className="text-4xl font-bold bg-gradient-to-r from-blue-500 to-cyan-500 bg-clip-text text-transparent">
                      {vulnerabilities.filter(v => v.source === 'NVD').length}
                    </p>
                  </div>
                  <div className="h-12 w-px bg-slate-700" aria-hidden="true"></div>
                  <div className="flex-1 min-w-[180px]">
                    <p className="text-sm font-medium text-slate-500 uppercase tracking-widest mb-2">Total Tracked</p>
                    <p className="text-4xl font-bold text-white">
                      {vulnerabilities.length}
                    </p>
                  </div>
                </div>
              </section>

              {/* Vulnerability Cards with semantic HTML and microdata */}
              <section id="vulnerabilities" aria-label="Latest vulnerabilities" className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-16">
                {vulnerabilities.map((vuln) => (
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
                        <div className="flex items-center gap-3">
                          <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold border ${getSourceColor(vuln.source)} transition-colors`}>
                            {vuln.source}
                          </span>
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
                        {vuln.description.length > 200 
                          ? `${vuln.description.substring(0, 200)}...` 
                          : vuln.description}
                      </p>
                      
                      {/* Product Info */}
                      {vuln.product && vuln.vendor && (
                        <div className="mb-4 p-3 bg-slate-900/50 rounded-lg border border-slate-700">
                          <span className="text-xs font-medium text-slate-400 uppercase tracking-wide">Affected Product</span>
                          <p className="text-sm font-semibold text-slate-200 mt-1" itemProp="about">{vuln.vendor} {vuln.product}</p>
                        </div>
                      )}
                      
                      {/* Footer */}
                      <div className="flex justify-between items-center pt-4 border-t border-slate-700">
                        <time className="text-xs text-slate-500 font-medium" dateTime={vuln.published} itemProp="datePublished">
                          {new Date(vuln.published).toLocaleDateString('en-US', { 
                            year: 'numeric', 
                            month: 'short', 
                            day: 'numeric' 
                          })}
                        </time>
                        <a 
                          href={vuln.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-red-400 hover:text-red-300 text-sm font-semibold inline-flex items-center space-x-1 transition-colors"
                          itemProp="url"
                          aria-label={`View full details for ${vuln.cveId || vuln.title}`}
                        >
                          <span>View Details</span>
                          <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                        </a>
                      </div>
                    </div>
                  </article>
                ))}
              </section>
            </>
          ) : (
            <div className="text-center py-24 bg-slate-950 rounded-xl border border-slate-800">
              <div className="inline-flex items-center justify-center w-20 h-20 bg-slate-900 rounded-full mb-6 border border-slate-700">
                <AlertTriangle className="w-12 h-12 text-slate-600" />
              </div>
              <h2 className="text-2xl font-bold text-white mb-3">No Vulnerabilities Loaded</h2>
              <p className="text-slate-400 mb-8 max-w-md mx-auto">Unable to fetch vulnerability data at this time. Please try again later or check our other resources.</p>
              <div className="flex justify-center gap-4">
                <Link 
                  href="/dashboard"
                  className="px-6 py-3 rounded-lg bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white font-semibold transition-all duration-300 shadow-lg shadow-red-500/20 hover:shadow-red-500/40"
                >
                  Try Dashboard
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

          {/* Information Section with structured data */}
          <section aria-label="Data sources information" className="mt-16 bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
            <div className="bg-gradient-to-r from-red-600/20 to-orange-600/20 border-b border-slate-800 px-8 py-6">
              <h2 className="text-2xl font-bold text-white flex items-center space-x-3">
                <Shield className="w-6 h-6 text-red-500" />
                <span>Trusted Data Sources</span>
              </h2>
            </div>
            <div className="p-8">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="relative p-6 bg-gradient-to-br from-red-500/10 to-red-600/5 rounded-lg border border-red-500/30 hover:border-red-500/50 transition-colors group">
                  <div className="absolute inset-0 bg-gradient-to-br from-red-600/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity rounded-lg" />
                  <div className="relative">
                    <div className="flex items-center mb-3">
                      <span className="w-4 h-4 bg-red-500 rounded-full mr-3" aria-hidden="true"></span>
                      <h3 className="font-bold text-red-300 text-lg">CISA KEV Catalog</h3>
                    </div>
                    <p className="text-sm text-slate-300 leading-relaxed">
                      <strong>Known Exploited Vulnerabilities</strong> catalog maintained by the Cybersecurity and Infrastructure Security Agency. These are actively exploited vulnerabilities requiring immediate attention.
                    </p>
                  </div>
                </div>
                <div className="relative p-6 bg-gradient-to-br from-blue-500/10 to-blue-600/5 rounded-lg border border-blue-500/30 hover:border-blue-500/50 transition-colors group">
                  <div className="absolute inset-0 bg-gradient-to-br from-blue-600/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity rounded-lg" />
                  <div className="relative">
                    <div className="flex items-center mb-3">
                      <span className="w-4 h-4 bg-blue-500 rounded-full mr-3" aria-hidden="true"></span>
                      <h3 className="font-bold text-blue-300 text-lg">National Vulnerability Database</h3>
                    </div>
                    <p className="text-sm text-slate-300 leading-relaxed">
                      The <strong>NVD</strong> provides comprehensive CVE information with CVSS scoring maintained by NIST. Essential for vulnerability management and security operations.
                    </p>
                  </div>
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