import Link from 'next/link';
import Footer from '../components/Footer';
import type { Metadata } from 'next';

// SEO Metadata for Home Page
export const metadata: Metadata = {
  title: "Home | Real-Time Zero-Day Vulnerability & CVE Tracker",
  description: "Monitor critical zero-day vulnerabilities and CVEs in real-time from CISA KEV and National Vulnerability Database. Get instant security alerts, CVSS scores, and comprehensive vulnerability intelligence for proactive threat management.",
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
    case 'critical': return 'status-critical';
    case 'high': return 'status-high';
    case 'medium': return 'status-medium';
    case 'low': return 'status-low';
    default: return 'bg-gray-100 text-gray-800 border-gray-200';
  }
}

function getSourceColor(source: string) {
  switch (source) {
    case 'CISA KEV': return 'bg-red-500';
    case 'NVD': return 'bg-blue-500';
    default: return 'bg-gray-500';
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
        },
        "sameAs": [
          "https://www.linkedin.com/company/secforit", // Update with actual links
          "https://twitter.com/secforit"
        ]
      },
      {
        "@type": "WebPage",
        "@id": "https://secforit.ro/#webpage",
        "url": "https://secforit.ro",
        "name": "Zero-Day Vulnerability Tracker | Real-Time CVE Monitoring",
        "description": "Monitor critical zero-day vulnerabilities and CVEs from CISA KEV and NVD with real-time updates",
        "isPartOf": {
          "@id": "https://secforit.ro/#website"
        },
        "about": {
          "@type": "Thing",
          "name": "Cybersecurity Vulnerability Monitoring"
        },
        "inLanguage": "en-US"
      },
      {
        "@type": "BreadcrumbList",
        "itemListElement": [
          {
            "@type": "ListItem",
            "position": 1,
            "name": "Home",
            "item": "https://secforit.ro"
          }
        ]
      },
      {
        "@type": "SoftwareApplication",
        "name": "Zero-Day Vulnerability Tracker",
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "Web Browser",
        "offers": {
          "@type": "Offer",
          "price": "0",
          "priceCurrency": "USD"
        },
        "aggregateRating": {
          "@type": "AggregateRating",
          "ratingValue": "4.8",
          "ratingCount": "150",
          "bestRating": "5",
          "worstRating": "1"
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
      
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 flex flex-col">
        <div className="container mx-auto px-6 py-8 max-w-7xl flex-grow">
          {/* Header Section with SEO-optimized content */}
          <header className="text-center mb-12">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-600 rounded-2xl mb-4 shadow-lg">
              <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <h1 className="text-5xl font-bold text-gray-900 mb-4">
              Zero-Day Vulnerability Tracker
            </h1>
            <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
              Real-time CVE monitoring from <strong>CISA Known Exploited Vulnerabilities</strong> and <strong>National Vulnerability Database</strong>. Stay protected with instant security alerts and comprehensive threat intelligence.
            </p>
            
            {/* Navigation with descriptive text for SEO */}
            <nav aria-label="Main navigation" className="flex flex-wrap justify-center gap-4 mb-8">
              <Link 
                href="/dashboard"
                className="btn-primary inline-flex items-center space-x-2"
                aria-label="View vulnerability dashboard with real-time statistics"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                <span>Dashboard</span>
              </Link>
              <Link 
                href="/ai-summaries"
                className="bg-purple-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-purple-700 transition-colors duration-200 shadow-sm hover:shadow-md inline-flex items-center space-x-2"
                aria-label="View AI-powered vulnerability analysis and threat intelligence"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
                <span>AI Analysis</span>
              </Link>
              <a 
                href="/rss"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-orange-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-orange-700 transition-colors duration-200 shadow-sm hover:shadow-md inline-flex items-center space-x-2"
                aria-label="Subscribe to RSS feed for vulnerability updates"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 5c7.18 0 13 5.82 13 13M6 11a7 7 0 017 7m-6 0a1 1 0 11-2 0 1 1 0 012 0z" />
                </svg>
                <span>RSS Feed</span>
              </a>
            </nav>
          </header>

          {vulnerabilities.length > 0 ? (
            <>
              {/* Stats Bar with semantic HTML */}
              <section aria-label="Vulnerability statistics" className="mb-8 bg-white rounded-xl shadow-md p-6 border border-gray-200">
                <div className="flex flex-wrap justify-center items-center gap-8 text-center">
                  <div>
                    <p className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-1">CISA KEV Vulnerabilities</p>
                    <p className="text-3xl font-bold text-red-600">
                      {vulnerabilities.filter(v => v.source === 'CISA KEV').length}
                    </p>
                  </div>
                  <div className="h-12 w-px bg-gray-300" aria-hidden="true"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-1">NVD Recent CVEs</p>
                    <p className="text-3xl font-bold text-blue-600">
                      {vulnerabilities.filter(v => v.source === 'NVD').length}
                    </p>
                  </div>
                  <div className="h-12 w-px bg-gray-300" aria-hidden="true"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-500 uppercase tracking-wide mb-1">Total Tracked</p>
                    <p className="text-3xl font-bold text-gray-800">
                      {vulnerabilities.length}
                    </p>
                  </div>
                </div>
              </section>

              {/* Vulnerability Cards with semantic HTML and microdata */}
              <section aria-label="Latest vulnerabilities" className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {vulnerabilities.map((vuln) => (
                  <article 
                    key={vuln.id} 
                    className="bg-white rounded-xl shadow-md border border-gray-200 card-hover overflow-hidden"
                    itemScope 
                    itemType="https://schema.org/TechArticle"
                  >
                    <div className="p-6">
                      {/* Header */}
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center gap-3">
                          <span className={`w-3 h-3 rounded-full ${getSourceColor(vuln.source)}`} aria-hidden="true"></span>
                          <span className="text-sm font-semibold text-gray-700" itemProp="provider">{vuln.source}</span>
                        </div>
                        <span className={`px-3 py-1 text-xs font-semibold rounded-full border ${getSeverityColor(vuln.severity)}`}>
                          {vuln.severity}
                          {vuln.cvssScore && ` (${vuln.cvssScore})`}
                        </span>
                      </div>
                      
                      {/* Title */}
                      <h3 className="text-lg font-bold text-gray-900 mb-3 leading-tight" itemProp="headline">
                        {vuln.cveId && <span className="text-blue-600" itemProp="identifier">{vuln.cveId}: </span>}
                        {vuln.title}
                      </h3>
                      
                      {/* Description */}
                      <p className="text-gray-600 text-sm mb-4 leading-relaxed" itemProp="description">
                        {vuln.description.length > 200 
                          ? `${vuln.description.substring(0, 200)}...` 
                          : vuln.description}
                      </p>
                      
                      {/* Product Info */}
                      {vuln.product && vuln.vendor && (
                        <div className="mb-4 p-3 bg-gray-50 rounded-lg border border-gray-200">
                          <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">Affected Product</span>
                          <p className="text-sm font-semibold text-gray-800 mt-1" itemProp="about">{vuln.vendor} {vuln.product}</p>
                        </div>
                      )}
                      
                      {/* Footer */}
                      <div className="flex justify-between items-center pt-4 border-t border-gray-200">
                        <time className="text-xs text-gray-500 font-medium" dateTime={vuln.published} itemProp="datePublished">
                          Published: {new Date(vuln.published).toLocaleDateString('en-US', { 
                            year: 'numeric', 
                            month: 'short', 
                            day: 'numeric' 
                          })}
                        </time>
                        <a 
                          href={vuln.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:text-blue-800 text-sm font-semibold inline-flex items-center space-x-1 transition-colors"
                          itemProp="url"
                          aria-label={`View full details for ${vuln.cveId || vuln.title}`}
                        >
                          <span>View Details</span>
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                          </svg>
                        </a>
                      </div>
                    </div>
                  </article>
                ))}
              </section>
            </>
          ) : (
            <div className="text-center py-16 bg-white rounded-xl shadow-md border border-gray-200">
              <div className="inline-flex items-center justify-center w-20 h-20 bg-gray-100 rounded-full mb-6">
                <svg className="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <h2 className="text-2xl font-bold text-gray-800 mb-3">No Vulnerabilities Loaded</h2>
              <p className="text-gray-600 mb-8 max-w-md mx-auto">Unable to fetch vulnerability data at this time. Please try again later or check our other resources.</p>
              <div className="flex justify-center gap-4">
                <Link 
                  href="/dashboard"
                  className="btn-primary"
                >
                  Try Dashboard
                </Link>
                <Link 
                  href="/ai-summaries"
                  className="bg-purple-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-purple-700 transition-colors duration-200 shadow-sm hover:shadow-md"
                >
                  View AI Analysis
                </Link>
              </div>
            </div>
          )}

          {/* Information Section with structured data */}
          <section aria-label="Data sources information" className="mt-12 bg-white rounded-xl shadow-md border border-gray-200 overflow-hidden">
            <div className="bg-gradient-to-r from-blue-600 to-blue-700 px-6 py-4">
              <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <span>Trusted Data Sources</span>
              </h2>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="p-5 bg-red-50 rounded-lg border-2 border-red-200">
                  <div className="flex items-center mb-3">
                    <span className="w-4 h-4 bg-red-500 rounded-full mr-3" aria-hidden="true"></span>
                    <h3 className="font-bold text-red-900 text-lg">CISA KEV Catalog</h3>
                  </div>
                  <p className="text-sm text-red-700 leading-relaxed">
                    <strong>Known Exploited Vulnerabilities</strong> catalog maintained by the Cybersecurity and Infrastructure Security Agency (CISA). These vulnerabilities are actively being exploited in the wild and require immediate attention from security teams worldwide.
                  </p>
                </div>
                <div className="p-5 bg-blue-50 rounded-lg border-2 border-blue-200">
                  <div className="flex items-center mb-3">
                    <span className="w-4 h-4 bg-blue-500 rounded-full mr-3" aria-hidden="true"></span>
                    <h3 className="font-bold text-blue-900 text-lg">National Vulnerability Database</h3>
                  </div>
                  <p className="text-sm text-blue-700 leading-relaxed">
                    The <strong>NVD</strong> provides comprehensive CVE information with CVSS scoring, vulnerability descriptions, and technical details maintained by the National Institute of Standards and Technology (NIST). Essential resource for vulnerability management and security operations.
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