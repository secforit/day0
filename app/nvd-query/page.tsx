import NVDQueryConsole from './NVDQueryConsole';
import Link from 'next/link';
import Footer from '@/components/Footer';
import type { Metadata } from 'next';
import { Database, Home, Brain } from 'lucide-react';

export const metadata: Metadata = {
  title: "NVD Query Console | Advanced CVE Search Interface",
  description: "Advanced query interface for the National Vulnerability Database (NVD) API. Search CVEs by severity, CPE, CWE, CVSS scores, keywords, and more. Export results in JSON or CSV format for vulnerability management and security research.",
  keywords: [
    "NVD query",
    "CVE search",
    "vulnerability database",
    "CVSS search",
    "CPE query",
    "CWE search",
    "security research",
    "vulnerability management",
    "NVD API",
    "CVE filtering",
    "security intelligence",
    "threat research"
  ],
  openGraph: {
    title: "NVD Query Console | Advanced CVE Search",
    description: "Advanced query interface for searching the National Vulnerability Database with multiple filters and export capabilities.",
    url: "https://secforit.ro/nvd-query",
    type: "website",
  },
  alternates: {
    canonical: "https://secforit.ro/nvd-query"
  }
};

function generateStructuredData() {
  return {
    "@context": "https://schema.org",
    "@type": "WebApplication",
    "name": "NVD Query Console",
    "description": "Advanced query interface for the National Vulnerability Database",
    "url": "https://secforit.ro/nvd-query",
    "applicationCategory": "SecurityApplication",
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "USD"
    },
    "featureList": [
      "CVE ID search",
      "CVSS severity filtering",
      "CPE and CWE queries",
      "Date range filtering",
      "Keyword search",
      "CISA KEV filtering",
      "JSON/CSV export",
      "Real-time API integration"
    ],
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
          "name": "NVD Query",
          "item": "https://secforit.ro/nvd-query"
        }
      ]
    }
  };
}

export default async function NVDQueryPage() {
  const structuredData = generateStructuredData();
  
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
      />
      
      <div className="min-h-screen bg-black text-white overflow-hidden">
        {/* Animated background */}
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

        {/* Breadcrumb */}
        <div className="relative max-w-7xl mx-auto px-6 pt-6">
          <nav aria-label="Breadcrumb" className="mb-4">
            <ol className="flex items-center space-x-2 text-sm text-slate-400">
              <li>
                <Link href="/" className="hover:text-white transition-colors">
                  Home
                </Link>
              </li>
              <li aria-hidden="true">/</li>
              <li className="text-white font-medium">NVD Query</li>
            </ol>
          </nav>
        </div>

        {/* Header */}
        <div className="relative max-w-7xl mx-auto px-6 pt-8 pb-12">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-10 gap-4">
            <div>
              <div className="flex items-center space-x-4 mb-4">
                <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-cyan-700 rounded-xl flex items-center justify-center shadow-2xl shadow-blue-500/30">
                  <Database className="w-10 h-10 text-white" />
                </div>
                <div>
                  <h1 className="text-5xl font-bold bg-gradient-to-r from-blue-500 via-cyan-400 to-blue-500 bg-clip-text text-transparent">
                    NVD Query Console
                  </h1>
                </div>
              </div>
              <p className="text-xl text-slate-400">
                Advanced search interface for the National Vulnerability Database
              </p>
            </div>
            <div className="flex gap-3">
              <Link 
                href="/ai-summaries"
                className="px-6 py-3 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-semibold transition-all duration-300 shadow-lg shadow-purple-500/20 hover:shadow-purple-500/40 inline-flex items-center space-x-2"
              >
                <Brain className="w-5 h-5" />
                <span>AI Analysis</span>
              </Link>
              <Link 
                href="/"
                className="px-6 py-3 rounded-lg border border-slate-700 hover:border-slate-600 bg-slate-900 hover:bg-slate-800 text-white font-semibold transition-colors inline-flex items-center space-x-2"
              >
                <Home className="w-5 h-5" />
                <span>Home</span>
              </Link>
            </div>
          </div>

          {/* Feature Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
            <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 hover:border-blue-500/50 transition-all">
              <div className="flex items-center mb-3">
                <div className="w-10 h-10 bg-blue-500/10 rounded-lg flex items-center justify-center border border-blue-500/20 mr-3">
                  <svg className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                </div>
                <h3 className="text-lg font-bold text-white">Advanced Filtering</h3>
              </div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Query by CVE ID, CPE, CWE, CVSS scores, severity levels, and date ranges with precise control.
              </p>
            </div>

            <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 hover:border-blue-500/50 transition-all">
              <div className="flex items-center mb-3">
                <div className="w-10 h-10 bg-green-500/10 rounded-lg flex items-center justify-center border border-green-500/20 mr-3">
                  <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                </div>
                <h3 className="text-lg font-bold text-white">Export Options</h3>
              </div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Export query results in JSON or CSV format for further analysis, reporting, or integration with other tools.
              </p>
            </div>

            <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 hover:border-blue-500/50 transition-all">
              <div className="flex items-center mb-3">
                <div className="w-10 h-10 bg-purple-500/10 rounded-lg flex items-center justify-center border border-purple-500/20 mr-3">
                  <svg className="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
                <h3 className="text-lg font-bold text-white">Real-Time API</h3>
              </div>
              <p className="text-sm text-slate-400 leading-relaxed">
                Direct integration with NVD API 2.0 for up-to-date vulnerability data with rate limiting compliance.
              </p>
            </div>
          </div>

          {/* Main Console */}
          <NVDQueryConsole />

          {/* Example Queries */}
          <div className="mt-12 bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
            <div className="bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border-b border-slate-800 px-6 py-4">
              <h2 className="text-xl font-bold text-white">Example Queries</h2>
            </div>
            <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-700">
                <h4 className="text-sm font-bold text-white mb-2">Critical CISA KEV Vulnerabilities</h4>
                <code className="text-xs text-slate-400 block">hasKev: true, cvssV3Severity: CRITICAL</code>
                <p className="text-xs text-slate-500 mt-2">Find actively exploited critical vulnerabilities</p>
              </div>

              <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-700">
                <h4 className="text-sm font-bold text-white mb-2">Windows 10 Vulnerabilities</h4>
                <code className="text-xs text-slate-400 block break-all">cpeName: cpe:2.3:o:microsoft:windows_10:*</code>
                <p className="text-xs text-slate-500 mt-2">Search by Common Platform Enumeration</p>
              </div>

              <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-700">
                <h4 className="text-sm font-bold text-white mb-2">SQL Injection Vulnerabilities</h4>
                <code className="text-xs text-slate-400 block">cweId: CWE-89, cvssV3Severity: HIGH</code>
                <p className="text-xs text-slate-500 mt-2">Filter by Common Weakness Enumeration</p>
              </div>

              <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-700">
                <h4 className="text-sm font-bold text-white mb-2">Recent Critical Vulnerabilities</h4>
                <code className="text-xs text-slate-400 block">pubStartDate: 2024-01-01, severity: CRITICAL</code>
                <p className="text-xs text-slate-500 mt-2">Date-based filtering for recent threats</p>
              </div>
            </div>
          </div>

          {/* Documentation */}
          <div className="mt-12 bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
            <div className="bg-gradient-to-r from-blue-600/20 to-cyan-600/20 border-b border-slate-800 px-6 py-4">
              <h2 className="text-xl font-bold text-white">Query Documentation</h2>
            </div>
            <div className="p-6">
              <div className="space-y-4 text-sm">
                <div>
                  <h4 className="font-semibold text-white mb-2">Common Platform Enumeration (CPE)</h4>
                  <p className="text-slate-400 leading-relaxed">
                    CPE names identify specific product versions. Format: <code className="text-blue-400 font-mono text-xs">cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other</code>
                  </p>
                </div>

                <div>
                  <h4 className="font-semibold text-white mb-2">Common Weakness Enumeration (CWE)</h4>
                  <p className="text-slate-400 leading-relaxed">
                    CWE IDs categorize vulnerability types. Common examples: CWE-79 (XSS), CWE-89 (SQL Injection), CWE-787 (Out-of-bounds Write), CWE-22 (Path Traversal).
                  </p>
                </div>

                <div>
                  <h4 className="font-semibold text-white mb-2">CVSS Severity Levels</h4>
                  <div className="grid grid-cols-4 gap-2 mt-2">
                    <div className="bg-red-500/10 border border-red-500/30 rounded px-3 py-2 text-center">
                      <div className="text-xs font-bold text-red-300">CRITICAL</div>
                      <div className="text-xs text-slate-400">9.0-10.0</div>
                    </div>
                    <div className="bg-orange-500/10 border border-orange-500/30 rounded px-3 py-2 text-center">
                      <div className="text-xs font-bold text-orange-300">HIGH</div>
                      <div className="text-xs text-slate-400">7.0-8.9</div>
                    </div>
                    <div className="bg-yellow-500/10 border border-yellow-500/30 rounded px-3 py-2 text-center">
                      <div className="text-xs font-bold text-yellow-300">MEDIUM</div>
                      <div className="text-xs text-slate-400">4.0-6.9</div>
                    </div>
                    <div className="bg-green-500/10 border border-green-500/30 rounded px-3 py-2 text-center">
                      <div className="text-xs font-bold text-green-300">LOW</div>
                      <div className="text-xs text-slate-400">0.1-3.9</div>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="font-semibold text-white mb-2">API Limitations</h4>
                  <ul className="list-disc list-inside space-y-1 text-slate-400">
                    <li>Maximum date range: 120 consecutive days</li>
                    <li>Maximum results per page: 2,000</li>
                    <li>Rate limit: {process.env.NVD_API_KEY ? '50 requests/30s' : '5 requests/30s (get API key for higher limits)'}</li>
                    <li>Results are cached for 30 minutes</li>
                  </ul>
                </div>

                <div>
                  <h4 className="font-semibold text-white mb-2">Resources</h4>
                  <div className="flex flex-wrap gap-3 mt-2">
                    <a
                      href="https://nvd.nist.gov/developers/vulnerabilities"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 text-sm font-medium hover:underline"
                    >
                      NVD API Documentation →
                    </a>
                    <a
                      href="https://nvd.nist.gov/developers/request-an-api-key"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 text-sm font-medium hover:underline"
                    >
                      Request API Key →
                    </a>
                    <a
                      href="https://cpe.mitre.org/specification/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 text-sm font-medium hover:underline"
                    >
                      CPE Specification →
                    </a>
                    <a
                      href="https://cwe.mitre.org/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 text-sm font-medium hover:underline"
                    >
                      CWE Database →
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <Footer />
      </div>
    </>
  );
}