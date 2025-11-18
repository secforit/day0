import { 
  fetchLatestVulnerabilitiesWithSummaries,
  type VulnerabilitySummary,
  type VulnerabilityData 
} from '@/app/actions/ai-summary-actions';
import AIVulnerabilitySummaries from './AIVulnerabilitySummaries';
import Footer from '@/components/Footer';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: "AI Vulnerability Analysis | AI-Powered Threat Intelligence",
  description: "Advanced AI-powered vulnerability analysis using Mixtral-8x7b for comprehensive threat intelligence. Get detailed CVE summaries, impact assessments, and actionable security recommendations from trusted sources including CISA KEV and NVD.",
  keywords: [
    "AI vulnerability analysis",
    "AI threat intelligence",
    "machine learning security",
    "automated CVE analysis",
    "AI cybersecurity",
    "vulnerability assessment AI",
    "Mixtral AI",
    "security intelligence automation",
    "AI-powered threat detection",
    "automated security analysis"
  ],
  openGraph: {
    title: "AI Vulnerability Analysis | AI-Powered Threat Intelligence",
    description: "Get AI-powered analysis of critical vulnerabilities with comprehensive threat intelligence and actionable security recommendations.",
    url: "https://secforit.ro/ai-summaries",
    type: "website",
  },
  alternates: {
    canonical: "https://secforit.ro/ai-summaries"
  }
};

function generateAIStructuredData() {
  return {
    "@context": "https://schema.org",
    "@type": "WebPage",
    "name": "AI Vulnerability Analysis",
    "description": "AI-powered vulnerability analysis and threat intelligence",
    "url": "https://secforit.ro/ai-summaries",
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
          "name": "AI Analysis",
          "item": "https://secforit.ro/ai-summaries"
        }
      ]
    },
    "mainEntity": {
      "@type": "SoftwareApplication",
      "name": "AI Vulnerability Analyzer",
      "applicationCategory": "SecurityApplication",
      "offers": {
        "@type": "Offer",
        "price": "0",
        "priceCurrency": "USD"
      },
      "featureList": [
        "AI-powered CVE analysis",
        "Threat intelligence automation",
        "Real-time vulnerability assessment",
        "CVSS score interpretation",
        "Actionable security recommendations"
      ]
    }
  };
}

export default async function AISummariesPage() {
  const result = await fetchLatestVulnerabilitiesWithSummaries(10);
  const structuredData = generateAIStructuredData();
  
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
                <a href="/" className="hover:text-white transition-colors">
                  Home
                </a>
              </li>
              <li aria-hidden="true">/</li>
              <li className="text-white font-medium">AI Analysis</li>
            </ol>
          </nav>
        </div>

        <div className="relative max-w-7xl mx-auto px-6 pb-8 flex-grow">
          <AIVulnerabilitySummaries 
            initialSummaries={result.summaries}
            timestamp={result.timestamp}
            error={result.error}
          />
        </div>
        <Footer />
      </div>
    </>
  );
}